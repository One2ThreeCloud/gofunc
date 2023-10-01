package serve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/getkin/kin-openapi/openapi3"
)

const schemaPrefix = "#/components/schemas/"
const reqFieldTag = "schema"
const rspFieldTag = "json"

var API_JSON = ""

type openapi struct {
	model   *openapi3.T
	swagger []byte

	namePkg map[string]string
}

func newOpenapi(path string) *openapi {
	o := &openapi{}
	o.model = &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "Service API",
			Version: "1.0",
		},
		Paths: openapi3.Paths{},
		Components: &openapi3.Components{
			Schemas: openapi3.Schemas{},
		},
	}
	o.swagger = []byte(fmt.Sprintf(swaggerHTML, path))
	o.namePkg = map[string]string{}
	return o
}

func (o *openapi) addMethod(info *methodInfo) {
	methodName := info.handlerName + info.method.Name
	rspContent := openapi3.Content{"application/json": {
		Schema: &openapi3.SchemaRef{
			Ref: schemaPrefix + methodName + "Response",
		},
	},
	}

	oper := &openapi3.Operation{
		OperationID: methodName,
		Tags:        []string{info.handlerName},
		Summary:     "",
		Responses: openapi3.Responses{
			"200": &openapi3.ResponseRef{
				Value: &openapi3.Response{
					Content: rspContent,
				},
			},
			"400": &openapi3.ResponseRef{
				Value: &openapi3.Response{
					Content: openapi3.Content{"application/json": {
						Schema: &openapi3.SchemaRef{
							Ref: schemaPrefix + "APIError",
						},
					},
					},
				},
			},
			"500": &openapi3.ResponseRef{
				Value: &openapi3.Response{
					Content: openapi3.Content{"application/json": {
						Schema: &openapi3.SchemaRef{
							Ref: schemaPrefix + "APIError",
						},
					},
					},
				},
			},
		},
	}

	if info.httpMethod == "PUT" || info.httpMethod == "POST" {
		oper.RequestBody = &openapi3.RequestBodyRef{
			Value: &openapi3.RequestBody{
				Required: true,
				Content: openapi3.Content{"application/json": {
					Schema: &openapi3.SchemaRef{
						Ref: schemaPrefix + methodName + "Request",
					},
				},
				}},
		}
		o.parseType(methodName+"Request", reqFieldTag, info.reqType)
	} else {
		oper.Parameters = o.buildParameter(methodName+"Request", info.reqType)
	}

	if _, ok := o.model.Paths[info.path]; !ok {
		o.model.Paths[info.path] = &openapi3.PathItem{}
	}

	if info.httpMethod == "GET" {
		o.model.Paths[info.path].Get = oper
	} else if info.httpMethod == "DELETE" {
		o.model.Paths[info.path].Delete = oper
	} else if info.httpMethod == "PUT" {
		o.model.Paths[info.path].Put = oper
	} else if info.httpMethod == "POST" {
		o.model.Paths[info.path].Post = oper
	}

	o.parseType(methodName+"Response", rspFieldTag, info.rspType)
}

func (o *openapi) buildParameter(typeName string, reqType reflect.Type) openapi3.Parameters {
	elemType := reqType
	if elemType.Kind() == reflect.Ptr { // pointer to struct
		elemType = reqType.Elem()
	}
	if elemType.Kind() != reflect.Struct {
		// not struct
		return nil
	}
	o.parseType(typeName, reqFieldTag, reqType)
	ref := o.model.Components.Schemas[typeName]

	ret := openapi3.Parameters{}
	for key, v := range ref.Value.Properties {
		required := inArray(v.Value.Required, key)
		p := &openapi3.Parameter{In: "query", Name: key, Required: required}
		ret = append(ret, &openapi3.ParameterRef{Value: p})
	}
	return ret
}

func inArray(arr []string, t string) bool {
	for _, v := range arr {
		if v == t {
			return true
		}
	}
	return false
}

func (o *openapi) checkSchemaExists(parentType string, st reflect.Type) bool {
	name := parentType + st.Name()
	pkg := st.PkgPath()
	if vv, ok := o.namePkg[name]; ok {
		if vv != pkg {
			panic(fmt.Sprintf("%s is defined in multiple package: %s %s", name, pkg, vv))
		}
		return true
	}
	o.namePkg[name] = pkg
	return false
}

func (o *openapi) getSwaggerHTML() []byte {
	return o.swagger
}

func (o *openapi) getOpenAPIV3() []byte {
	bs, err := o.model.MarshalJSON()
	if err != nil {
		return []byte{}
	}
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, bs, "", "    "); err != nil {
		return []byte{}
	}
	return prettyJSON.Bytes()
}

func (o *openapi) parseType(typeName, tag string, rType reflect.Type) *openapi3.SchemaRef {
	elemType := rType
	if elemType.Kind() == reflect.Ptr { // pointer to struct
		elemType = rType.Elem()
	}
	var apiType string
	var subType *openapi3.SchemaRef
	var properties openapi3.Schemas
	switch elemType.Kind() {
	case reflect.String:
		apiType = "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		apiType = "integer"
	case reflect.Float32, reflect.Float64:
		apiType = "number"
	case reflect.Bool:
		apiType = "boolean"
	case reflect.Map:
		apiType = "object"
		keyType := elemType.Key()
		if keyType == nil || keyType.Kind() != reflect.String {
			panic(fmt.Sprintf("map key type for %s should be string instand of %v", elemType.Name(), elemType.Kind()))
		}
		subType = o.parseType(typeName, tag, elemType.Elem())
	case reflect.Array, reflect.Slice:
		apiType = "array"
		subType = o.parseType(typeName, tag, elemType.Elem())
	case reflect.Interface:
		apiType = "string"
	case reflect.Struct:
		apiType = "object"
		if !o.checkSchemaExists(typeName, elemType) {
			stName := elemType.Name()
			if !unicode.IsUpper(rune(stName[0])) {
				panic(fmt.Sprintf("%s must be exportable", stName))
			}
			properties = openapi3.Schemas{}
			var requiredFields []string
			for i := 0; i < elemType.NumField(); i++ {
				field := elemType.Field(i)
				fieldType := field.Type
				if fieldType.Kind() == reflect.Ptr {
					fieldType = field.Type.Elem()
				}
				if !unicode.IsUpper(rune(field.Name[0])) {
					continue
				}
				fieldTag := field.Tag.Get(tag)
				if fieldTag == "-" {
					continue
				}
				if fieldTag == "" {
					fieldTag = field.Name
				}
				fieldSchema := o.parseType(typeName+fieldType.Name(), tag, fieldType)

				validateTag := field.Tag.Get("validate")
				if strings.HasSuffix(validateTag, "required") || strings.Contains(validateTag, "required,") {
					requiredFields = append(requiredFields, fieldTag)
				}

				if fieldSchema.Value != nil {
					fieldSchema.Value.Title = field.Name
				}

				properties[fieldTag] = fieldSchema
			}
			title := elemType.Name()
			schemaRef := &openapi3.SchemaRef{Value: &openapi3.Schema{
				Type:        "object",
				Properties:  properties,
				Description: title,
				Required:    requiredFields,
			}}
			o.model.Components.Schemas[typeName] = schemaRef
		}
	default:
		panic(fmt.Sprintf("unsupported type %v for %s", elemType.Kind(), elemType.Name()))
	}
	if apiType == "array" {
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{Type: "array", Items: subType},
		}
	} else if apiType == "object" && subType != nil { // map
		trueVal := true
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{Type: "object", AdditionalProperties: openapi3.AdditionalProperties{
				Has:    &trueVal,
				Schema: subType,
			},
			},
		}
	} else if apiType == "object" {
		return &openapi3.SchemaRef{Ref: schemaPrefix + elemType.Name()}
	}
	return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: apiType}}
}

var swaggerHTML = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta
      name="description"
      content="SwaggerUI"
    />
    <title>SwaggerUI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui.css" />
  </head>
  <body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui-bundle.js" crossorigin></script>
  <script src="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui-standalone-preset.js" crossorigin></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '%sapi.json',
        dom_id: '#swagger-ui',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout",
      });
    };
  </script>
  </body>
</html>`
