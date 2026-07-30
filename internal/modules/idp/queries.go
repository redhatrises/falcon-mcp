package idp

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// This file builds the GraphQL query strings submitted to the Identity
// Protection endpoint. Each builder renders one investigation type's query.

// jsonList renders a string slice as a JSON array literal for embedding in a
// GraphQL query. A nil or empty slice renders as [] rather than null, since null
// is not a valid value for the list arguments these queries build.
func jsonList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	b, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// jsonString renders a string as a JSON string literal.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// allowedTimelineCategories is the set of GraphQL enum values the timeline
// query accepts for its categories argument, matching the values documented on
// InvestigateInput.TimelineEventTypes.
var allowedTimelineCategories = []string{
	"ACTIVITY",
	"NOTIFICATION",
	"THREAT",
	"ENTITY",
	"AUDIT",
	"POLICY",
	"SYSTEM",
}

// filterTimelineCategories returns the allowlisted timeline categories from
// eventTypes, preserving the caller's order, along with the values it rejected
// so the caller can report them. Duplicates are passed through unchanged.
//
// Timeline categories are GraphQL enums, which are bare identifiers rather than
// strings, so they cannot be JSON-encoded the way the query's string arguments
// are. Restricting them to known values is what keeps caller input from being
// interpolated into the query as executable structure.
func filterTimelineCategories(eventTypes []string) (kept, rejected []string) {
	if len(eventTypes) == 0 {
		return nil, nil
	}
	kept = make([]string, 0, len(eventTypes))
	for _, et := range eventTypes {
		if slices.Contains(allowedTimelineCategories, et) {
			kept = append(kept, et)
			continue
		}
		rejected = append(rejected, et)
	}
	return kept, rejected
}

// buildEntityDetailsQuery renders the entity-details query for a batch of IDs.
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

// buildTimelineQuery renders the activity-timeline query for one entity.
//
// The entity ID and time bounds are embedded as JSON string literals so caller
// input cannot terminate the literal and inject query structure. Categories are
// GraphQL enums and must stay unquoted, so they are allowlisted instead.
func buildTimelineQuery(entityID, startTime, endTime string, eventTypes []string, limit int) string {
	filters := []string{fmt.Sprintf(`sourceEntityQuery: {entityIds: %s}`, jsonList([]string{entityID}))}

	if startTime != "" {
		filters = append(filters, fmt.Sprintf(`startTime: %s`, jsonString(startTime)))
	}
	if endTime != "" {
		filters = append(filters, fmt.Sprintf(`endTime: %s`, jsonString(endTime)))
	}
	// Allowlisting happens here, at the point of embedding, so the guarantee holds
	// regardless of what the caller passed. Rejected values are reported by
	// timelinesBatch, which filters once for the whole batch.
	if categories, _ := filterTimelineCategories(eventTypes); len(categories) > 0 {
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

// buildRelationshipQuery renders the relationship-graph query for one entity,
// including its recursive association nesting driven by relationshipDepth.
//
// The entity ID is embedded as a JSON string literal, matching
// buildEntityDetailsQuery, so caller input cannot inject query structure.
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
// given depth.
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

// buildRiskAssessmentQuery renders the risk-assessment query for a batch of IDs.
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
