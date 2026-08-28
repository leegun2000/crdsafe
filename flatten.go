package main

import (
	"strconv"
	"strings"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// nodeKind says how the walk reached a node. Inferring this from the path string cannot work:
// a CRD may legally declare a property named "items" or "not".
type nodeKind uint8

const (
	nodeRoot nodeKind = iota
	nodeProperty
	nodeItems    // array element
	nodeMapValue // additionalProperties value
	nodeAllOf
	nodeAnyOf
	nodeOneOf
	nodeNot
)

// schemaNode is one entry of a flattened CRD version schema.
type schemaNode struct {
	instance string // the path a live object uses: spec.tags.key
	parent   string // schema path of the enclosing node, "" at the root
	kind     nodeKind
	// inLogic marks a node reached through allOf/anyOf/oneOf/not. Changes under one of those are
	// reported wholesale by logicFindings, because the direction of a node-local change there
	// depends on the whole boolean expression.
	inLogic bool
	props   *apiextv1.JSONSchemaProps
}

// flatten walks a version's OpenAPI schema and keys every node by the same path grammar crdify's
// FlattenCRDVersion uses, so a crdify finding can be looked up here. Alongside each key it records
// the path an actual custom resource would use, which is what correlation joins on. Deriving that
// by stripping "items" and "additionalProperties" from the string instead would mangle any CRD
// with a property genuinely named one of those.
func flatten(v apiextv1.CustomResourceDefinitionVersion) map[string]schemaNode {
	out := map[string]schemaNode{}
	if v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
		return out
	}
	walk(v.Schema.OpenAPIV3Schema, "^", "", schemaNode{kind: nodeRoot}, out)
	return out
}

// walk mirrors crdify's SchemaHas traversal order. Order matters: a later visit overwrites an
// earlier one at the same key, which is how crdify resolves a property literally named "items".
func walk(s *apiextv1.JSONSchemaProps, schemaPath, instance string, self schemaNode, out map[string]schemaNode) {
	if s == nil {
		return
	}
	self.instance, self.props = instance, s
	out[schemaPath] = self

	child := func(kind nodeKind) schemaNode {
		return schemaNode{
			parent: schemaPath, kind: kind,
			inLogic: self.inLogic || kind == nodeAllOf || kind == nodeAnyOf || kind == nodeOneOf || kind == nodeNot,
		}
	}

	if s.Items != nil {
		// An array element shares its parent's instance path; the index is elided.
		if s.Items.Schema != nil {
			walk(s.Items.Schema, schemaPath+".items", instance, child(nodeItems), out)
		}
		for i := range s.Items.JSONSchemas {
			walk(&s.Items.JSONSchemas[i], schemaPath+".items["+strconv.Itoa(i)+"]", instance, child(nodeItems), out)
		}
	}
	for _, q := range []struct {
		name string
		list []apiextv1.JSONSchemaProps
		kind nodeKind
	}{
		{"allOf", s.AllOf, nodeAllOf}, {"anyOf", s.AnyOf, nodeAnyOf}, {"oneOf", s.OneOf, nodeOneOf},
	} {
		for i := range q.list {
			walk(&q.list[i], schemaPath+"."+q.name+"["+strconv.Itoa(i)+"]", instance, child(q.kind), out)
		}
	}
	if s.Not != nil {
		walk(s.Not, schemaPath+".not", instance, child(nodeNot), out)
	}
	for name := range s.Properties {
		p := s.Properties[name]
		walk(&p, schemaPath+"."+name, joinPath(instance, name), child(nodeProperty), out)
	}
	if s.AdditionalProperties != nil && s.AdditionalProperties.Schema != nil {
		// A map value shares its parent's instance path; the key is elided.
		walk(s.AdditionalProperties.Schema, schemaPath+".additionalProperties", instance, child(nodeMapValue), out)
	}
}

// logicPaths collects the schema paths that sit inside a logical combinator in either version,
// so findings there can be deferred to logicFindings.
func logicPaths(crds ...*apiextv1.CustomResourceDefinition) removedPaths {
	out := removedPaths{}
	for _, crd := range crds {
		for _, v := range crd.Spec.Versions {
			for path, node := range flatten(v) {
				if !node.inLogic {
					continue
				}
				if out[v.Name] == nil {
					out[v.Name] = map[string]bool{}
				}
				out[v.Name][path] = true
			}
		}
	}
	return out
}

// pathIndex resolves a crdify schema path to an instance path. crdify reports a version per
// finding, and the same schema path can mean different things in different versions.
type pathIndex struct {
	perVersion map[string]map[string]string
	merged     map[string]string
}

func newPathIndex(crd *apiextv1.CustomResourceDefinition) pathIndex {
	idx := pathIndex{perVersion: map[string]map[string]string{}, merged: map[string]string{}}
	for _, v := range crd.Spec.Versions {
		m := map[string]string{}
		for path, node := range flatten(v) {
			m[path] = node.instance
			idx.merged[path] = node.instance
		}
		idx.perVersion[v.Name] = m
	}
	return idx
}

// instance looks up a schema path. version is either "v1" or crdify's cross-version "v1 -> v2".
func (p pathIndex) instance(version, schemaPath string) string {
	names := []string{version}
	if before, after, found := strings.Cut(version, " -> "); found {
		names = []string{after, before}
	}
	for _, name := range names {
		if got, ok := p.perVersion[name][schemaPath]; ok {
			return got
		}
	}
	if got, ok := p.merged[schemaPath]; ok {
		return got
	}
	// A path present in neither version can only come from the removed side; the removal itself
	// is reported separately, so a best-effort string form is enough to keep the report readable.
	return strings.TrimPrefix(strings.TrimPrefix(schemaPath, "^"), ".")
}
