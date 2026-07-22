package idp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// This file builds the GraphQL query strings, mirroring the Python idp module's
// _build_*_query helpers verbatim in structure. The field selections match the
// Python queries exactly so the returned shapes are identical.

// jsonList renders a string slice as a JSON array literal for embedding in a
// GraphQL query, mirroring the Python json.dumps(list).
func jsonList(items []string) string {
	b, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// jsonString renders a string as a JSON string literal, mirroring
// json.dumps(str).
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// allowedTimelineCategories is the documented set of GraphQL enum values for
// timeline categories (see InvestigateInput.TimelineEventTypes). Values outside
// this set are dropped so unquoted enum interpolation cannot inject GraphQL.
var allowedTimelineCategories = map[string]struct{}{
	"ACTIVITY":     {},
	"NOTIFICATION": {},
	"THREAT":       {},
	"ENTITY":       {},
	"AUDIT":        {},
	"POLICY":       {},
	"SYSTEM":       {},
}

// filterTimelineCategories keeps only allowlisted timeline category enums in
// the order supplied, dropping unknown or injection-shaped values.
func filterTimelineCategories(eventTypes []string) []string {
	if len(eventTypes) == 0 {
		return nil
	}
	out := make([]string, 0, len(eventTypes))
	for _, et := range eventTypes {
		if _, ok := allowedTimelineCategories[et]; ok {
			out = append(out, et)
		}
	}
	return out
}

// buildEntityDetailsQuery mirrors _build_entity_details_query.
func buildEntityDetailsQuery(entityIDs []string, includeRiskFactors, includeAssociations, includeIncidents, includeAccounts bool) string {
	fields := []string{
		"entityId",
		"primaryDisplayName",
		"secondaryDisplayName",
		"type",
		"riskScore",
		"riskScoreSeverity",
	}

	if includeRiskFactors {
		fields = append(fields, `
                riskFactors {
                    type
                    severity
                }
            `)
	}

	if includeAssociations {
		fields = append(fields, `
                associations {
                    bindingType
                    ... on EntityAssociation {
                        entity {
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                            type
                        }
                    }
                    ... on LocalAdminLocalUserAssociation {
                        accountName
                    }
                    ... on LocalAdminDomainEntityAssociation {
                        entityType
                        entity {
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                        }
                    }
                    ... on GeoLocationAssociation {
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                    }
                }
            `)
	}

	if includeIncidents {
		fields = append(fields, `
                openIncidents(first: 10) {
                    nodes {
                        type
                        startTime
                        endTime
                        compromisedEntities {
                            entityId
                            primaryDisplayName
                        }
                    }
                }
            `)
	}

	if includeAccounts {
		fields = append(fields, `
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain
                        samAccountName
                        ou
                        servicePrincipalNames
                        passwordAttributes {
                            lastChange
                            strength
                        }
                        expirationTime
                    }
                    ... on SsoUserAccountDescriptor {
                        dataSource
                        mostRecentActivity
                        title
                        creationTime
                        passwordAttributes {
                            lastChange
                        }
                    }
                    ... on AzureCloudServiceAdapterDescriptor {
                        registeredTenantType
                        appOwnerOrganizationId
                        publisherDomain
                        signInAudience
                    }
                    ... on CloudServiceAdapterDescriptor {
                        dataSourceParticipantIdentifier
                    }
                }
            `)
	}

	fieldsString := strings.Join(fields, "\n")

	return fmt.Sprintf(`
        query {
            entities(entityIds: %s, first: 50) {
                nodes {
                    %s
                }
            }
        }
        `, jsonList(entityIDs), fieldsString)
}

// buildTimelineQuery mirrors _build_timeline_query.
//
// String values (entity ID, start/end times) are embedded via jsonString /
// jsonList so quotes, backslashes, and control characters cannot break out of
// GraphQL string context. Timeline categories are GraphQL enums and must remain
// unquoted identifiers; they are restricted to allowedTimelineCategories.
func buildTimelineQuery(entityID, startTime, endTime string, eventTypes []string, limit int) string {
	filters := []string{fmt.Sprintf(`sourceEntityQuery: {entityIds: %s}`, jsonList([]string{entityID}))}

	if startTime != "" {
		filters = append(filters, fmt.Sprintf(`startTime: %s`, jsonString(startTime)))
	}
	if endTime != "" {
		filters = append(filters, fmt.Sprintf(`endTime: %s`, jsonString(endTime)))
	}
	if categories := filterTimelineCategories(eventTypes); len(categories) > 0 {
		// Format allowlisted event types as unquoted GraphQL enums.
		filters = append(filters, fmt.Sprintf("categories: [%s]", strings.Join(categories, ", ")))
	}

	filterString := strings.Join(filters, ", ")

	return fmt.Sprintf(`
        query {
            timeline(%s, first: %d) {
                nodes {
                    eventId
                    eventType
                    eventSeverity
                    timestamp
                    ... on TimelineUserOnEndpointActivityEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineAuthenticationEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineAlertEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                    }
                    ... on TimelineDceRpcEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineFailedAuthenticationEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineSuccessfulAuthenticationEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineServiceAccessEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineFileOperationEvent {
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineLdapSearchEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineRemoteCodeExecutionEvent {
                        sourceEntity {
                            entityId
                            primaryDisplayName
                        }
                        targetEntity {
                            entityId
                            primaryDisplayName
                        }
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }
                    ... on TimelineConnectorConfigurationEvent {
                        category
                    }
                    ... on TimelineConnectorConfigurationAddedEvent {
                        category
                    }
                    ... on TimelineConnectorConfigurationDeletedEvent {
                        category
                    }
                    ... on TimelineConnectorConfigurationModifiedEvent {
                        category
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        `, filterString, limit)
}

// buildRelationshipQuery mirrors _build_relationship_analysis_query, including
// its recursive association nesting driven by relationshipDepth.
//
// The entity ID is embedded via jsonList so user-supplied IDs cannot break out
// of the GraphQL string list (same approach as buildEntityDetailsQuery).
func buildRelationshipQuery(entityID string, relationshipDepth int, includeRiskContext bool, limit int) string {
	riskFields := ""
	if includeRiskContext {
		riskFields = `
                riskScore
                riskScoreSeverity
                riskFactors {
                    type
                    severity
                }
            `
	}

	associationFields := buildAssociationFields(relationshipDepth, riskFields)

	return fmt.Sprintf(`
        query {
            entities(entityIds: %s, first: %d) {
                nodes {
                    entityId
                    primaryDisplayName
                    secondaryDisplayName
                    type
                    %s
                    %s
                }
            }
        }
        `, jsonList([]string{entityID}), limit, riskFields, associationFields)
}

// buildAssociationFields recursively builds nested association selections to the
// given depth, mirroring the Python inner build_association_fields closure.
func buildAssociationFields(depth int, riskFields string) string {
	if depth <= 0 {
		return ""
	}
	nested := ""
	if depth > 1 {
		nested = buildAssociationFields(depth-1, riskFields)
	}

	return fmt.Sprintf(`
                associations {
                    bindingType
                    ... on EntityAssociation {
                        entity {
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                            type
                            %s
                            %s
                        }
                    }
                    ... on LocalAdminLocalUserAssociation {
                        accountName
                    }
                    ... on LocalAdminDomainEntityAssociation {
                        entityType
                        entity {
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                            type
                            %s
                            %s
                        }
                    }
                    ... on GeoLocationAssociation {
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                    }
                }
            `, riskFields, nested, riskFields, nested)
}

// buildRiskAssessmentQuery mirrors _build_risk_assessment_query.
func buildRiskAssessmentQuery(entityIDs []string, includeRiskFactors bool) string {
	riskFields := `
            riskScore
            riskScoreSeverity
        `
	if includeRiskFactors {
		riskFields += `
                riskFactors {
                    type
                    severity
                }
            `
	}

	return fmt.Sprintf(`
        query {
            entities(entityIds: %s, first: 50) {
                nodes {
                    entityId
                    primaryDisplayName
                    %s
                }
            }
        }
        `, jsonList(entityIDs), riskFields)
}
