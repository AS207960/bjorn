use chrono::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct IODEFRoot {
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IODEF-Document")]
    pub message: IODEFDocument,
}

/// The IODEF-Document class is the top level class in the IODEF data
/// model. All IODEF documents are an instance of this class.
#[derive(Debug, Serialize, Deserialize)]
pub struct IODEFDocument {
    /// The IODEF specification version number to which this IODEF document conforms.
    #[serde(rename = "$attr:version")]
    pub version: Version,
    /// A language identifier per Section 2.12 of W3C.XML whose values and form are described in RFC5646.
    #[serde(rename = "$attr:xml:lang")]
    pub lang: String,
    /// A free-form string to convey processing instructions to the recipient of the document.
    /// Its semantics must be negotiated out of band.
    #[serde(rename = "$attr:format-id", default, skip_serializing_if="Option::is_none")]
    pub format_id: Option<String>,
    /// A globally unique identifier for the CSIRT generating the document to deconflict private
    /// extensions used in the document. The fully qualified domain name (FQDN) associated
    /// with the CSIRT MUST be used as the identifier.
    #[serde(rename = "$attr:private-enum-name", default, skip_serializing_if="Option::is_none")]
    pub private_enum_name: Option<String>,
    /// An organizationally unique identifier for an extension used in the document.
    /// If this attribute is set, the private-enum-name MUST also be set.
    #[serde(rename = "$attr:private-enum-id", default, skip_serializing_if="Option::is_none")]
    pub private_enum_id: Option<String>,

    /// The information related to a single incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Incident")]
    pub incidents: Vec<Incident>,
    /// Mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Version {
    #[serde(rename = "2.00")]
    V2
}

/// The Incident class describes commonly exchanged information when
/// reporting or sharing derived analysis from security incidents.
#[derive(Debug, Serialize, Deserialize)]
pub struct Incident {
    /// The purpose attribute describes the rationale for documenting the information in this class.
    /// It is closely related to the Expectation class.
    #[serde(rename = "$attr:purpose")]
    pub purpose: Purpose,
    /// A means by which to extend the purpose attribute.
    #[serde(rename = "$attr:ext-purpose", default, skip_serializing_if="Option::is_none")]
    pub ext_purpose: Option<String>,
    /// The status attribute conveys the state in a workflow where the incident is currently found.
    #[serde(rename = "$attr:status")]
    pub status: Status,
    /// A means by which to extend the status attribute.
    #[serde(rename = "$attr:ext-status", default, skip_serializing_if="Option::is_none")]
    pub ext_status: Option<String>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default)]
    pub restriction: Restriction,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    /// The observable-id attribute tags information in the document as an
    /// observable so that it can be referenced later in the description of
    /// an indicator.  The value of this attribute is a unique identifier in
    /// the scope of the document.  It is used by the ObservableReference
    /// class to enumerate observables when defining an indicator with the
    /// IndicatorData class.
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,
    /// A language identifier per Section 2.12 of W3C.XML whose values and form are described in RFC5646.
    #[serde(rename = "$attr:xml:lang")]
    pub lang: String,

    /// An incident tracking number assigned to this incident by the CSIRT that generated the IODEF document.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IncidentID")]
    pub incident_id: IncidentID,
    /// The incident tracking numbers used by other CSIRTs to refer to the incident described in the document.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AlternativeID", default, skip_serializing_if="Option::is_none")]
    pub alternative_id: Option<AlternativeID>,
    /// Related activity and attribution of this activity.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RelatedActivity", default, skip_serializing_if="Vec::is_empty")]
    pub related_activity: Vec<RelatedActivity>,
    /// The time the incident was first detected.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DetectTime", default, skip_serializing_if="Option::is_none")]
    pub detect_time: Option<DateTime<Utc>>,
    /// The time the incident started.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}StartTime", default, skip_serializing_if="Option::is_none")]
    pub start_time: Option<DateTime<Utc>>,
    /// The time the incident ended.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EndTime", default, skip_serializing_if="Option::is_none")]
    pub end_time: Option<DateTime<Utc>>,
    /// The time the site recovered from the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RecoveryTime", default, skip_serializing_if="Option::is_none")]
    pub recovery_time: Option<DateTime<Utc>>,
    /// The time the incident was reported.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ReportTime", default, skip_serializing_if="Option::is_none")]
    pub report_time: Option<DateTime<Utc>>,
    /// The time the content in this Incident class was generated.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}GenerationTime")]
    pub generation_time: DateTime<Utc>,
    /// A free-form text description of the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// The means by which this incident was detected.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Discovery", default, skip_serializing_if="Vec::is_empty")]
    pub discovery: Vec<Discovery>,
    /// A characterization of the impact of the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Assessment", default, skip_serializing_if="Vec::is_empty")]
    pub assessment: Vec<Assessment>,
    /// The techniques used by the threat actor in the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Method", default, skip_serializing_if="Vec::is_empty")]
    pub method: Vec<Method>,
    /// Contact information for the parties involved in the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Contact")]
    pub contact: Vec<Contact>,
    /// Description of the events comprising the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EventData", default, skip_serializing_if="Vec::is_empty")]
    pub event_data: Vec<EventData>,
    /// Indicators from the analysis of an incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IndicatorData", default, skip_serializing_if="Option::is_none")]
    pub indicator_data: Option<IndicatorData>,
    /// A log of significant events or actions that occurred during the course of handling the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}History", default, skip_serializing_if="Option::is_none")]
    pub history: Option<History>,
    /// Mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Purpose {
    /// The incident was sent for trace-back purposes.
    #[serde(rename = "traceback")]
    Traceback,
    /// The incident was sent to request aid in mitigating the described activity.
    #[serde(rename = "mitigation")]
    Mitigation,
    /// The incident was sent to comply with reporting requirements.
    #[serde(rename = "reporting")]
    Reporting,
    /// The incident was sent to convey indicators that should be monitored.
    #[serde(rename = "watch")]
    Watch,
    /// The incident was sent for purposes specified in the Expectation class.
    #[serde(rename = "other")]
    Other,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Status {
    /// The incident is newly reported, and no action has been taken.
    #[serde(rename = "new")]
    New,
    /// The incident is under investigation.
    #[serde(rename = "in-progress")]
    InProgress,
    /// The incident has been forwarded to another party for handling.
    #[serde(rename = "forwarded")]
    Forwarded,
    /// The investigation into the activity in this incident has concluded.
    #[serde(rename = "resolved")]
    Resolved,
    /// The described activity has not yet been detected.
    #[serde(rename = "future")]
    Future,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The restriction attribute indicates the disclosure guidelines to
/// which the sender expects the recipient to adhere for the information
/// represented in this class and its children.  This guideline provides
/// no security since there are no technical means to ensure that the
/// recipient of the document handles the information as the sender
/// requested.
#[derive(Debug, Serialize, Deserialize)]
pub enum Restriction {
    /// The information can be shared according to an information disclosure policy pre-arranged by the communicating parties.
    #[serde(rename = "default")]
    Default,
    ///  The information can be freely distributed without restriction.
    #[serde(rename = "public")]
    Public,
    /// The information may be shared within a closed community of peers, partners, or affected parties, but cannot be openly published.
    #[serde(rename = "partner")]
    Partner,
    /// The information may be shared only within the organization with individuals that have a need to know.
    #[serde(rename = "need-to-know")]
    NeedToKnow,
    /// The information may not be shared.
    #[serde(rename = "private")]
    Private,
    /// Same as 'public'.
    #[serde(rename = "white")]
    White,
    ///  Same as 'partner'.
    #[serde(rename = "green")]
    Green,
    /// Same as 'need-to-know'.
    #[serde(rename = "amber")]
    Amber,
    /// Same as 'private'.
    #[serde(rename = "red")]
    Red,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

impl Default for Restriction {
    fn default() -> Self {
        Self::Private
    }
}

/// The IncidentID class represents a tracking number that is unique in
/// the context of the CSIRT.  It serves as an identifier for an incident
/// or a document identifier when sharing indicators.  This identifier
/// would serve as an index into a CSIRT's incident handling or knowledge
/// management system.
///
/// The combination of the name attribute and the string in the element
/// content MUST be a globally unique identifier describing the activity.
/// Documents generated by a given CSIRT MUST NOT reuse the same value
/// unless they are referencing the same incident.
#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentID {
    #[serde(rename = "$value")]
    pub value: String,
    /// An identifier describing the CSIRT that created the document.
    /// In order to have a globally unique CSIRT name,
    /// the fully qualified domain name associated with the CSIRT MUST be used.
    #[serde(rename = "$attr:name")]
    pub name: String,
    /// An identifier referencing a subset of the named incident.
    #[serde(rename = "$attr:instance", default, skip_serializing_if="Option::is_none")]
    pub instance: Option<String>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
}

/// The AlternativeID class lists the tracking numbers used by CSIRTs,
/// other than the one generating the document, to refer to the identical
/// activity described in the IODEF document. A tracking number listed
/// as an AlternativeID references the same incident detected by another
/// CSIRT. The tracking numbers of the CSIRT that generated the IODEF
/// document must never be considered an AlternativeID.
#[derive(Debug, Serialize, Deserialize)]
pub struct AlternativeID {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    /// The tracking number of another CSIRT.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IncidentID")]
    pub ids: Vec<IncidentID>,
}

/// The RelatedActivity class relates the information described in the
/// rest of the document to previously observed incidents or activity and
/// allows attribution to a specific actor or campaign.
#[derive(Debug, Serialize, Deserialize)]
pub struct RelatedActivity {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    ///  The tracking number of a related incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IncidentID", default, skip_serializing_if="Vec::is_empty")]
    pub incident_ids: Vec<IncidentID>,
    /// A URL to activity related to this incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}URL", default, skip_serializing_if="Vec::is_empty")]
    pub urls: Vec<String>,
    /// The threat actor to whom the incident activity is attributed.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ThreatActor", default, skip_serializing_if="Vec::is_empty")]
    pub threat_actor: Vec<ThreatActor>,
    /// The campaign of a given threat actor to whom the described activity is attributed.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Campaign", default, skip_serializing_if="Vec::is_empty")]
    pub campaign: Vec<Campaign>,
    /// A reference to a related indicator.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IndicatorID", default, skip_serializing_if="Vec::is_empty")]
    pub indicator_id: Vec<IndicatorID>,
    /// An estimate of the confidence in attributing this RelatedActivity to the events described in the document.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Confidence", default, skip_serializing_if="Option::is_none")]
    pub confidence: Option<Confidence>,
    /// A description of how these relationships were derived.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// A mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// The ThreatActor class describes a threat actor.
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatActor {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    /// An identifier for the threat actor.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ThreatActorID", default, skip_serializing_if="Vec::is_empty")]
    pub ids: Vec<String>,
    /// A URL to a reference describing the threat actor.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}URL")]
    pub urls: Vec<String>,
    /// A description of the threat actor.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// A mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// The Campaign class describes a campaign of attacks by a threat actor.
#[derive(Debug, Serialize, Deserialize)]
pub struct Campaign {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    /// An identifier for the campaign.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}CampaignID", default, skip_serializing_if="Vec::is_empty")]
    pub ids: Vec<String>,
    /// A URL to a reference describing the campaign.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}URL", default, skip_serializing_if="Vec::is_empty")]
    pub urls: Vec<String>,
    /// A description of the campaign.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// A mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// The Contact class describes contact information for organizations and
/// personnel involved in the incident.  This class allows for the naming
/// of the involved party, specifying contact information for them, and
/// identifying their role in the incident.
#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    /// Indicates the role the contact fulfills.
    #[serde(rename = "$attr:role")]
    pub role: ContactRole,
    /// A means by which to extend the role attribute.
    #[serde(rename = "$attr:ext-role", default, skip_serializing_if="Option::is_none")]
    pub ext_role: Option<String>,
    /// Indicates the type of contact being described.
    #[serde(rename = "$attr:type")]
    pub contact_type: ContactType,
    /// A means by which to extend the type attribute.
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_type: Option<String>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    /// The name of the contact. The contact may either be an organization or a person.
    /// The type attribute disambiguates the semantics.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ContactName", default, skip_serializing_if="Vec::is_empty")]
    pub name: Vec<MLStringType>,
    /// The title for the individual named in the ContactName.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ContactTitle", default, skip_serializing_if="Vec::is_empty")]
    pub title: Vec<MLStringType>,
    /// A free-form text description of the contact.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// A handle name into the registry of the contact; see `RegistryHandle`.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RegistryHandle", default, skip_serializing_if="Vec::is_empty")]
    pub registry_handle: Vec<RegistryHandle>,
    /// The postal address of the contact; see `PostalAddress`.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}PostalAddress", default, skip_serializing_if="Vec::is_empty")]
    pub postal_address: Vec<PostalAddress>,
    /// The email address of the contact; see `Email`.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Email", default, skip_serializing_if="Vec::is_empty")]
    pub email: Vec<Email>,
    /// The telephone number of the contact; see `Telephone`.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Telephone", default, skip_serializing_if="Vec::is_empty")]
    pub telephone: Vec<Telephone>,
    /// The timezone in which the contact resides.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Timezone", default, skip_serializing_if="Option::is_none")]
    pub timezone: Option<String>,
    /// A recursive definition of the Contact class.
    /// This definition can be used to group common data pertaining to multiple points of contact
    /// and is especially useful when listing multiple contacts at the same organization.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Contact", default, skip_serializing_if="Vec::is_empty")]
    pub contact: Vec<Contact>,
    /// A mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// Indicates the role the contact fulfills.
#[derive(Debug, Serialize, Deserialize)]
pub enum ContactRole {
    /// The entity that generates the document.
    #[serde(rename = "creator")]
    Creator,
    /// The entity that reported the information.
    #[serde(rename = "reporter")]
    Reporter,
    /// An administrative contact or business owner for an asset or organization.
    #[serde(rename = "admin")]
    Admin,
    /// An entity responsible for the day-to-day management of technical issues for an asset or organization.
    #[serde(rename = "tech")]
    Tech,
    /// An external hosting provider for an asset.
    #[serde(rename = "provider")]
    Provider,
    /// An end-user of an asset or part of an organization.
    #[serde(rename = "user")]
    User,
    /// An entity responsible for billing issues for an asset or organization.
    #[serde(rename = "billing")]
    Billing,
    /// An entity responsible for legal issues related to an asset or organization.
    #[serde(rename = "legal")]
    Legal,
    /// An entity responsible for handling abuse originating from an asset or organization.
    #[serde(rename = "abuse")]
    Abuse,
    /// An entity responsible for handling security issues for an asset or organization.
    #[serde(rename = "irt")]
    IRT,
    /// An entity that is to be kept informed about the events related to an asset or organization.
    #[serde(rename = "cc")]
    CC,
    /// A CSIRT or information-sharing organization coordinating activity related to an asset or organization.
    #[serde(rename = "cc-irt")]
    CCIRT,
    /// A law enforcement organization supporting the investigation of activity affecting an asset or organization.
    #[serde(rename = "leo")]
    LEO,
    /// The vendor that produces an asset.
    #[serde(rename = "vendor")]
    Vendor,
    /// A vendor that provides services.
    #[serde(rename = "vendor-services")]
    VendorServices,
    /// A victim in the incident.
    #[serde(rename = "victim")]
    Victim,
    /// A victim in the incident who has been notified.
    #[serde(rename = "victim-notified")]
    VictimNotified,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// Indicates the type of contact being described.
#[derive(Debug, Serialize, Deserialize)]
pub enum ContactType {
    /// The information for this contact references an individual.
    #[serde(rename = "person")]
    Person,
    /// The information for this contact references an organization.
    #[serde(rename = "organization")]
    Organisation,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The RegistryHandle class represents a handle into an Internet registry or community-specific database.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryHandle {
    /// The handle into a registry.
    #[serde(rename = "$value")]
    pub value: String,
    /// The database to which the handle belongs.
    #[serde(rename = "$attr:registry")]
    pub registry: RegistryHandleRegistry,
    /// A means by which to extend the registry attribute
    #[serde(rename = "$attr:ext-registry", default, skip_serializing_if="Option::is_none")]
    pub ext_registry: Option<String>,
}

/// The database to which the handle belongs.
#[derive(Debug, Serialize, Deserialize)]
pub enum RegistryHandleRegistry {
    /// Internet Network Information Center
    #[serde(rename = "internic")]
    InterNIC,
    /// Asia Pacific Network Information Center
    #[serde(rename = "apnic")]
    APNIC,
    /// American Registry for Internet Numbers
    #[serde(rename = "arin")]
    ARIN,
    /// Latin American and Caribbean Internet Addresses Registry
    #[serde(rename = "lacnic")]
    LACNIC,
    /// Reseaux IP Europeens
    #[serde(rename = "ripe")]
    RIPE,
    /// African Network Information Center
    #[serde(rename = "afrinic")]
    AFRINIC,
    /// A database local to the CSIRT
    #[serde(rename = "local")]
    Local,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The PostalAddress class specifies a postal address and associated annotation.
#[derive(Debug, Serialize, Deserialize)]
pub struct PostalAddress {
    /// Categorizes the type of address described in the PAddress class.
    #[serde(rename = "$attr:type", default, skip_serializing_if="Option::is_none")]
    pub address_type: Option<AddressType>,
    /// A means by which to extend the type attribute.
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_type: Option<String>,

    /// A postal address.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}PAddress")]
    pub p_address: MLStringType,
    /// A free-form text description of the address.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

/// Indicates the type of contact being described.
#[derive(Debug, Serialize, Deserialize)]
pub enum AddressType {
    /// An address describing a physical location.
    #[serde(rename = "street")]
    Street,
    /// An address to which correspondence should be sent.
    #[serde(rename = "mailing")]
    Mailing,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The Email class specifies an email address and associated annotation.
#[derive(Debug, Serialize, Deserialize)]
pub struct Email {
    /// Categorizes the type of email address described in the EmailTo class.
    #[serde(rename = "$attr:type", default, skip_serializing_if="Option::is_none")]
    pub email_type: Option<EmailType>,
    /// A means by which to extend the type attribute.
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_type: Option<String>,

    /// An email address.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailTo")]
    pub email: String,
    /// A free-form text description of the email address.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

/// Categorizes the type of email address described in the EmailTo class.
#[derive(Debug, Serialize, Deserialize)]
pub enum EmailType {
    /// An email address of an individual.
    #[serde(rename = "direct")]
    Direct,
    /// An email address regularly monitored for operational purposes.
    #[serde(rename = "hotline")]
    Hotline,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The Telephone class describes a telephone number and associated annotation.
#[derive(Debug, Serialize, Deserialize)]
pub struct Telephone {
    /// Categorizes the type of telephone number described in the TelephoneNumber class.
    #[serde(rename = "$attr:type", default, skip_serializing_if="Option::is_none")]
    pub phone_type: Option<EmailType>,
    /// A means by which to extend the type attribute.
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_type: Option<String>,

    /// A telephone number.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}TelephoneNumber")]
    pub phone_number: String,
    /// A free-form text description of the phone number.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

/// Categorizes the type of telephone number described in the TelephoneNumber class.
#[derive(Debug, Serialize, Deserialize)]
pub enum TelephoneType {
    /// A number of a wire-line (land-line) phone.
    #[serde(rename = "wired")]
    Wired,
    /// A number of a mobile phone.
    #[serde(rename = "mobile")]
    Mobile,
    /// A number to a fax machine.
    #[serde(rename = "fax")]
    Fax,
    /// A number to a regularly monitored operational hotline.
    #[serde(rename = "hotline")]
    Hotline,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The Discovery class describes how an incident was detected.
#[derive(Debug, Serialize, Deserialize)]
pub struct Discovery {
    /// Categorizes the techniques used to discover the incident.
    #[serde(rename = "$attr:source", default, skip_serializing_if="Option::is_none")]
    pub source: Option<DiscoverySource>,
    /// A means by which to extend the source attribute.
    #[serde(rename = "$attr:ext-source", default, skip_serializing_if="Option::is_none")]
    pub ext_source: Option<String>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    /// A free-form text description of how this incident was detected.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// Contact information for the party that discovered the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Contact", default, skip_serializing_if="Vec::is_empty")]
    pub contact: Vec<Contact>,
    /// Describes an application-specific configuration that detected the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DetectionPattern", default, skip_serializing_if="Vec::is_empty")]
    pub detection_pattern: Vec<DetectionPattern>,
}

/// Categorizes the techniques used to discover the incident.
#[derive(Debug, Serialize, Deserialize)]
pub enum DiscoverySource {
    /// Network Intrusion Detection or Prevention System.
    #[serde(rename = "nidps")]
    NIDPS,
    /// Host-based Intrusion Prevention System.
    #[serde(rename = "hips")]
    HIPS,
    /// Security Information and Event Management System.
    #[serde(rename = "siem")]
    SIEM,
    /// Antivirus or antispam software.
    #[serde(rename = "av")]
    AV,
    /// Contracted third-party monitoring service.
    #[serde(rename = "third-party-monitoring")]
    ThirdPartyMonitoring,
    /// The activity was discovered while investigating an unrelated incident.
    #[serde(rename = "incident")]
    Incident,
    /// Operating system logs.
    #[serde(rename = "os-log")]
    OSLog,
    /// Application logs.
    #[serde(rename = "application-log")]
    ApplicationLog,
    /// Network device logs.
    #[serde(rename = "device-log")]
    DeviceLog,
    /// Network flow analysis.
    #[serde(rename = "network-flow")]
    NetworkFlow,
    /// Passive DNS analysis.
    #[serde(rename = "passive-dns")]
    PassiveDNS,
    /// Manual investigation initiated based on notification of a new vulnerability or exploit.
    #[serde(rename = "investigation")]
    Investigation,
    /// Security audit.
    #[serde(rename = "audit")]
    Audit,
    /// A party within the organization reported the activity.
    #[serde(rename = "internal-notification")]
    InternalNotification,
    /// A party outside of the organization reported the activity.
    #[serde(rename = "external-notification")]
    ExternalNotification,
    /// A law enforcement organization notified the victim organization.
    #[serde(rename = "leo")]
    LEO,
    /// A customer or business partner reported the activity to the victim organization.
    #[serde(rename = "partner")]
    Partner,
    /// The threat actor directly or indirectly reported this activity to the victim organization.
    #[serde(rename = "actor")]
    Actor,
    /// Unknown detection approach.
    #[serde(rename = "unknown")]
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The DetectionPattern class describes a configuration or signature
/// that can be used by an Intrusion Detection System (IDS) / Intrusion
/// Prevention System (IPS), SIEM, antivirus, endpoint protection,
/// network analysis, malware analysis, or host forensics tool to
/// identify a particular phenomenon.  This class requires the
/// identification of the target application and allows the configuration
/// to be described in either free form or machine-readable form.
#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionPattern {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// The application for which the DetectionConfiguration or Description is being provided.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Application")]
    pub application: Application,
    /// A free-form text description of how to use the information provided in the Application or DetectionConfiguration classes.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// A machine-consumable configuration to find a pattern of activity.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DetectionConfiguration", default, skip_serializing_if="Vec::is_empty")]
    pub detection_configuration: Vec<String>,
}

/// The Method class describes the tactics, techniques, procedures, or
/// weakness used by the threat actor in an incident. This class
/// consists of both a list of references describing the attack methods
/// and weaknesses and a free-form text description.
#[derive(Debug, Serialize, Deserialize)]
pub struct Method {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    /// A reference to a vulnerability, malware sample, advisory, or analysis of an attack technique.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Reference", default, skip_serializing_if="Vec::is_empty")]
    pub reference: Vec<Reference>,
    /// A free-form text description of techniques, tactics, or procedures used by the threat actor.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    // TODO: add sci:AttackPattern
    // TODO: add sci:Vulnerability
    // TODO: add sci:Weakness
    /// Mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// The Reference class is an external reference to relevant information
/// such as a vulnerability, IDS alert, malware sample, advisory, or
/// attack technique.
#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    /// Reference identifier
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-enum-1.0}enum:ReferenceName", default, skip_serializing_if="Option::is_none")]
    pub id: Option<ReferenceName>,
    /// A URL to a reference.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}URL", default, skip_serializing_if="Vec::is_empty")]
    pub urls: Vec<String>,
    /// A free-form text description of this reference.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,
}

/// The ReferenceName class provides the XML representation for identifying an enumeration and specifying a value from it.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReferenceName {
    /// The identifier assigned to represent the particular enumeration object being referenced.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-enum-1.0}enum:ID")]
    pub id: String,
    /// Enumeration identifier.
    /// This value corresponds to an entry in the "Enumeration Reference Type Identifiers" IANA registry with an identical SpecIndex value.
    #[serde(rename = "$attr:specIndex")]
    pub spec_index: usize,
}

/// The Assessment class describes the repercussions of the incident to the victim.
#[derive(Debug, Serialize, Deserialize)]
pub struct Assessment {
    /// Specifies whether the assessment is describing actual or potential outcomes
    #[serde(rename = "$attr:occurrence", default, skip_serializing_if="Option::is_none")]
    pub occurrence: Option<Restriction>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// A free-form text description categorizing the type of incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IncidentCategory", default, skip_serializing_if="Vec::is_empty")]
    pub incident_category: Vec<MLStringType>,
    #[serde(rename = "$value", default, skip_serializing_if="Vec::is_empty")]
    pub impact: Vec<AssessmentImpact>,
    /// A counter with which to summarize the magnitude of the activity.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Counter", default, skip_serializing_if="Vec::is_empty")]
    pub counter: Vec<Counter>,
    /// A description of a mitigating factor relative to the impact on the victim organization.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}MitigatingFactor", default, skip_serializing_if="Vec::is_empty")]
    pub mitigating_factor: Vec<MLStringType>,
    /// A description of an underlying cause of the impact.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Cause", default, skip_serializing_if="Vec::is_empty")]
    pub cause: Vec<MLStringType>,
    /// An estimate of confidence in the impact assessment.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Confidence", default, skip_serializing_if="Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AssessmentImpact {
    /// A technical characterization of the impact of the incident activity on the victim's enterprise.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}SystemImpact")]
    SystemImpact(SystemImpact),
    /// Impact of the incident activity on the business functions of the victim organization.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}BusinessImpact")]
    BusinessImpact(BusinessImpact),
    /// A characterization of the victim organization due to the incident activity as a function of time.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}TimeImpact")]
    TimeImpact(TimeImpact),
    /// The financial loss due to the incident activity.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}MonetaryImpact")]
    MonetaryImpact(MonetaryImpact),
    /// The intended outcome to the victim sought by the threat actor.
    /// Defined identically to the BusinessImpact, but describes intent rather than the realized impact.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IntendedImpact")]
    IntendedImpact(BusinessImpact),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemImpact {
    /// An estimate of the relative severity of the activity.
    #[serde(rename = "$attr:severity", default, skip_serializing_if="Option::is_none")]
    pub severity: Option<Severity>,
    /// An indication whether the described activity was successful.
    #[serde(rename = "$attr:completion", default, skip_serializing_if="Option::is_none")]
    pub completion: Option<Completion>,
    /// Classifies the impact.
    #[serde(rename = "$attr:type")]
    pub impact_type: SystemImpactType,
    /// A means by which to extend the type attribute
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_type: Option<String>,

    /// A free-form text description of the impact to the system.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Completion {
    /// The attempted activity was not successful.
    #[serde(rename="failed")]
    Failed,
    /// The attempted activity was not successful.
    #[serde(rename="succeeded")]
    Succeeded,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SystemImpactType {
    /// Control was taken of a given account.
    #[serde(rename="takeover-account")]
    TakeoverAccount,
    /// Control was taken of a given service.
    #[serde(rename="takeover-service")]
    TakeoverService,
    /// Control was taken of a given system.
    #[serde(rename="takeover-system")]
    TakeoverSystem,
    /// A cyber-physical system was manipulated.
    #[serde(rename="cps-manipulation")]
    CpsManipulation,
    /// A cyber-physical system was damaged.
    #[serde(rename="cps-damage")]
    CpsDamage,
    /// Access to particular data was degraded or denied.
    #[serde(rename="availability-data")]
    AvailabilityData,
    /// Access to an account was degraded or denied.
    #[serde(rename="availability-account")]
    AvailabilityAccount,
    /// Access to a service was degraded or denied.
    #[serde(rename="availability-service")]
    AvailabilityService,
    /// Access to a system was degraded or denied.
    #[serde(rename="availability-system")]
    AvailabilitySystem,
    /// Hardware on a system was irreparably damaged.
    #[serde(rename="damaged-system")]
    DamagedSystem,
    /// Data on a system was deleted.
    #[serde(rename="damaged-data")]
    DamagedData,
    /// Sensitive or proprietary information was accessed or exfiltrated.
    #[serde(rename="breach-proprietary")]
    BreachProprietary,
    /// Personally identifiable information was accessed or exfiltrated.
    #[serde(rename="breach-privacy")]
    BreachPrivacy,
    /// Credential information was accessed or exfiltrated.
    #[serde(rename="breach-credential")]
    BreachCredential,
    /// System configuration or data inventory was access or exfiltrated.
    #[serde(rename="breach-configuration")]
    BreachConfiguration,
    /// Data on the system was modified.
    #[serde(rename="integrity-data")]
    IntegrityData,
    /// Application or system configuration was modified.
    #[serde(rename="integrity-configuration")]
    IntegrityConfiguration,
    /// Firmware of a hardware component was modified.
    #[serde(rename="integrity-hardware")]
    IntegrityHardware,
    /// Network traffic on the system was redirected.
    #[serde(rename="traffic-redirection")]
    TrafficRedirection,
    /// Network traffic emerging from a host or enclave was monitored.
    #[serde(rename="monitoring-traffic")]
    MonitoringTraffic,
    /// System activity (e.g., running processes, keystrokes) were monitored.
    #[serde(rename="monitoring-traffic")]
    MonitoringHost,
    /// Activity violated the system owner's acceptable use policy.
    #[serde(rename="policy")]
    Policy,
    /// The impact is unknown.
    #[serde(rename="unknown")]
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
}

/// The BusinessImpact class describes and characterizes the degree to which the function of the organization was impacted by the incident.
#[derive(Debug, Serialize, Deserialize)]
pub struct BusinessImpact {
    /// Characterizes the severity of the incident on business functions.
    #[serde(rename = "$attr:severity", default, skip_serializing_if="Option::is_none")]
    pub severity: Option<BusinessImpactSeverity>,
    /// A means by which to extend the severity attribute
    #[serde(rename = "$attr:ext-severity", default, skip_serializing_if="Option::is_none")]
    pub ext_severity: Option<String>,
    /// Characterizes the effect this incident had on the business.
    #[serde(rename = "$attr:type")]
    pub impact_type: BusinessImpactType,
    /// A means by which to extend the type attribute
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_type: Option<String>,

    /// A free-form text description of the impact to the organization.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BusinessImpactSeverity {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "unknown")]
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BusinessImpactType {
    /// Sensitive or proprietary information was accessed or exfiltrated.
    #[serde(rename="breach-proprietary")]
    BreachProprietary,
    ///  Personally identifiable information was accessed or exfiltrated.
    #[serde(rename="breach-privacy")]
    BreachPrivacy,
    /// Credential information was accessed or exfiltrated.
    #[serde(rename="breach-credential")]
    BreachCredential,
    /// Sensitive or proprietary information was changed or deleted.
    #[serde(rename="loss-of-integrity")]
    LossOfIntegrity,
    /// Service delivery was disrupted.
    #[serde(rename="loss-of-service")]
    LossOfService,
    /// Money was stolen.
    #[serde(rename="theft-financial")]
    TheftFinancial,
    /// Services were misappropriated.
    #[serde(rename="theft-service")]
    TheftService,
    /// The reputation of the organization's brand was diminished.
    #[serde(rename="degraded-reputation")]
    DegradedReputation,
    /// A cyber-physical system was damaged.
    #[serde(rename="asset-damage")]
    AssetDamage,
    /// A cyber-physical system was manipulated.
    #[serde(rename="asset-manipulation")]
    AssetManipulation,
    /// The incident resulted in legal or regulatory action.
    #[serde(rename="legal")]
    Legal,
    ///  The incident resulted in actors extorting the victim organization.
    #[serde(rename="extertion")]
    Extortion,
    /// The impact is unknown.
    #[serde(rename="unknown")]
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The TimeImpact class describes the impact of the incident on an
/// organization as a function of time. It provides a way to convey down
/// time and recovery time.
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeImpact {
    #[serde(rename = "$value")]
    pub value: f64,

    /// An estimate of the relative severity of the activity.
    #[serde(rename = "$attr:severity", default, skip_serializing_if="Option::is_none")]
    pub severity: Option<Severity>,
    /// Specifies the type of counter specified in the element content.
    #[serde(rename = "$attr:type")]
    pub metric: TimeMetric,
    /// A means by which to extend the metric attribute
    #[serde(rename = "$attr:ext-metric", default, skip_serializing_if="Option::is_none")]
    pub ext_metric: Option<String>,
    /// Defines the unit of time for the value in the element content.
    #[serde(rename = "$attr:duration", default, skip_serializing_if="Option::is_none")]
    pub duration: Option<Duration>,
    /// A means by which to extend the duration attribute
    #[serde(rename = "$attr:ext-unit", default, skip_serializing_if="Option::is_none")]
    pub ext_duration: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TimeMetric {
    /// Total staff time to recovery from the activity (e.g., 2 employees working 4 hours each would be 8 hours).
    #[serde(rename = "labor")]
    Labor,
    /// Elapsed time from the beginning of the recovery to its completion (i.e., wall-clock time).
    #[serde(rename = "elapsed")]
    Elapsed,
    /// Duration of time for which some provided service(s) was not available.
    #[serde(rename = "downtime")]
    Downtime,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The MonetaryImpact class describes the financial impact of the
/// activity on an organization.  For example, this impact may consider
/// losses due to the cost of the investigation or recovery, diminished
/// productivity of the staff, or a tarnished reputation that will affect
/// future opportunities.
#[derive(Debug, Serialize, Deserialize)]
pub struct MonetaryImpact {
    #[serde(rename = "$value")]
    pub value: f64,

    /// An estimate of the relative severity of the activity.
    #[serde(rename = "$attr:severity", default, skip_serializing_if="Option::is_none")]
    pub severity: Option<Severity>,
    /// Defines the currency in which the value in the element content is expressed.
    #[serde(rename = "$attr:currency", default, skip_serializing_if="Option::is_none")]
    pub currency: Option<String>
}

/// The History class is a log of the significant events or actions
/// performed by the involved parties during the course of handling the
/// incident.
#[derive(Debug, Serialize, Deserialize)]
pub struct History {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}HistoryItem")]
    pub items: Vec<HistoryItem>
}

/// The HistoryItem class is an entry in the History log
/// that documents a particular action or event that occurred in the
/// course of handling the incident. The details of the entry are a
/// free-form text description, but each can be categorized with the type
/// attribute.
#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryItem {
    /// Classifies a performed action or occurrence documented in this history log entry.
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub action: Option<Action>,
    /// A means by which to extend the action attribute.
    #[serde(rename = "$attr:ext-action", default, skip_serializing_if="Option::is_none")]
    pub ext_action: Option<String>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// A timestamp of this entry in the history log.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DateTime")]
    pub date_time: DateTime<Utc>,
    /// In a history log created by multiple parties, the IncidentID provides a mechanism to
    /// specify which CSIRT created a particular entry and references this organization's tracking
    /// number. When a single organization is maintaining the log, this class can be ignored.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IncidentID", default, skip_serializing_if="Option::is_none")]
    pub incident_id: Option<IncidentID>,
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Contact", default, skip_serializing_if="Option::is_none")]
    pub contact: Option<Contact>,
    /// A free-form text description of the action or event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// An identifier meaningful to the sender and recipient of this document that references a course of action.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DefinedCOA", default, skip_serializing_if="Vec::is_empty")]
    pub defined_coa: Vec<String>,
    /// Mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Action {
    /// No action is requested. Do nothing with the information.
    #[serde(rename = "nothing")]
    Nothing,
    /// Contact the site(s) identified as the source of the activity.
    #[serde(rename = "contact-source-site")]
    ContactSourceSite,
    /// Contact the site(s) identified as the target of the activity.
    #[serde(rename = "contact-target-site")]
    ContactTargetSite,
    /// Contact the originator of the document.
    #[serde(rename = "contact-sender")]
    ContactSender,
    /// Investigate the system(s) listed in the event.
    #[serde(rename = "investigate")]
    Investigate,
    /// Block traffic from the machine(s) listed as sources in the event.
    #[serde(rename = "block-host")]
    BlockHost,
    /// Block traffic from the network(s) lists as sources in the event.
    #[serde(rename = "block-network")]
    BlockNetwork,
    /// Block the port listed as sources in the event.
    #[serde(rename = "block-port")]
    BlockPort,
    /// Rate-limit the traffic from the machine(s) listed as sources in the event.
    #[serde(rename = "rate-limit-host")]
    RateLimitHost,
    /// Rate-limit the traffic from the network(s) lists as sources in the event.
    #[serde(rename = "rate-limit-network")]
    RateLimitNetwork,
    /// Rate-limit the port(s) listed as sources in the event.
    #[serde(rename = "rate-limit-port")]
    RateLimitPort,
    /// Redirect traffic from the intended recipient for further analysis.
    #[serde(rename = "redirect-traffic")]
    RedirectTraffic,
    /// Redirect traffic from systems listed in the event to a honeypot for further analysis.
    #[serde(rename = "honeypot")]
    Honeypot,
    /// Upgrade or patch the software or firmware on an asset listed in the event.
    #[serde(rename = "upgrade-software")]
    UpgradeSoftware,
    /// Reinstall the operating system or applications on an asset listed in the event.
    #[serde(rename = "rebuild-asset")]
    RebuildAsset,
    /// Change the configuration of an asset listed in the event to reduce the attack surface.
    #[serde(rename = "harden-asset")]
    HardenAsset,
    /// Remediate the activity in a way other than by rate-limiting or blocking.
    #[serde(rename = "remediate-other")]
    RemediateOther,
    /// Confirm receipt and begin triaging the incident.
    #[serde(rename = "status-triage")]
    StatusTriage,
    ///  Notify the sender when new information is received for this incident.
    #[serde(rename = "status-new-info")]
    StatusNewInfo,
    /// Watch for the described activity or indicators, and notify the sender when seen.
    #[serde(rename = "watch-and-report")]
    WatchAndReport,
    /// Train user to identify or mitigate the described threat.
    #[serde(rename = "training")]
    Training,
    /// Perform a predefined course of action (COA). The COA is named in the DefinedCOA class.
    #[serde(rename = "defined-coa")]
    DefinedCOA,
    /// Perform a custom action described in the Description class.
    #[serde(rename = "other")]
    Other,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The EventData class is a container class to organize data about events that occurred during an incident.
#[derive(Debug, Serialize, Deserialize)]
pub struct EventData {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default)]
    pub restriction: Restriction,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// A free-form text description of the event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// The time the event was first detected.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DetectTime", default, skip_serializing_if="Option::is_none")]
    detect_time: Option<DateTime<Utc>>,
    /// The time the event started.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}StartTime", default, skip_serializing_if="Option::is_none")]
    pub start_time: Option<DateTime<Utc>>,
    /// The time the event ended.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EndTime", default, skip_serializing_if="Option::is_none")]
    pub end_time: Option<DateTime<Utc>>,
    /// The time the site recovered from the event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RecoveryTime", default, skip_serializing_if="Option::is_none")]
    pub recovery_time: Option<DateTime<Utc>>,
    /// The time the event was reported.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ReportTime", default, skip_serializing_if="Option::is_none")]
    pub report_time: Option<DateTime<Utc>>,
    /// Contact information for the parties involved in the event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Contact", default, skip_serializing_if="Vec::is_empty")]
    pub contact: Vec<Contact>,
    /// The means by which this event was detected.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Discovery", default, skip_serializing_if="Vec::is_empty")]
    pub discovery: Vec<Discovery>,
    /// A characterization of the impact of the event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Assessment", default, skip_serializing_if="Vec::is_empty")]
    pub assessment: Vec<Assessment>,
    /// The techniques used by the threat actor in the event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Method", default, skip_serializing_if="Vec::is_empty")]
    pub method: Vec<Method>,
    /// A description of the systems or networks involved.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Flow", default, skip_serializing_if="Vec::is_empty")]
    pub flow: Vec<Flow>,
    /// The expected action to be performed by the recipient for the described event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Expectation", default, skip_serializing_if="Vec::is_empty")]
    pub expectation: Vec<Expectation>,
    /// Supportive data (e.g., log files) that provides additional information about the event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Record", default, skip_serializing_if="Vec::is_empty")]
    pub record: Vec<Record>,
    /// A recursive definition of the EventData class.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EventData", default, skip_serializing_if="Vec::is_empty")]
    pub event_data: Vec<EventData>,
    /// Mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// The Expectation class conveys to the recipient of the IODEF document the actions the sender is requesting.
#[derive(Debug, Serialize, Deserialize)]
pub struct Expectation {
    /// The entity expected to perform the action.
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub action: Option<Action>,
    /// A means by which to extend the action attribute.
    #[serde(rename = "$attr:ext-action", default, skip_serializing_if="Option::is_none")]
    pub ext_action: Option<String>,
    /// Indicates the desired priority of the action.
    #[serde(rename = "$attr:severity", default, skip_serializing_if="Option::is_none")]
    pub severity: Option<Severity>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// A free-form text description of the desired action(s).
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// An identifier meaningful to the sender and recipient of this document that references a course of action.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DefinedCOA", default, skip_serializing_if="Vec::is_empty")]
    pub defined_coa: Vec<String>,
    /// The time at which the sender would like the action performed.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}StartTime", default, skip_serializing_if="Option::is_none")]
    pub start_time: Option<DateTime<Utc>>,
    /// The time by which the sender expects the recipient to complete the action.
    /// If the recipient cannot complete the action before EndTime, the recipient MUST NOT carry out the action.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EndTime", default, skip_serializing_if="Option::is_none")]
    pub end_time: Option<DateTime<Utc>>,
    /// The entity expected to perform the action.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Contact", default, skip_serializing_if="Option::is_none")]
    pub contact: Option<Contact>,
}

/// The Flow class describes the systems and networks involved in the incident and the relationships between them.
#[derive(Debug, Serialize, Deserialize)]
pub struct Flow {
    /// A host or network involved in an event.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}System", default, skip_serializing_if="Vec::is_empty")]
    pub systems: Vec<System>,
}

/// The System class describes a system or network involved in an event
#[derive(Debug, Serialize, Deserialize)]
pub struct System {
    /// Classifies the role the host or network played in the incident,
    #[serde(rename = "$attr:category", default, skip_serializing_if="Option::is_none")]
    pub category: Option<SystemCategory>,
    /// A means by which to extend the category attribute.
    #[serde(rename = "$attr:ext-category", default, skip_serializing_if="Option::is_none")]
    pub ext_category: Option<String>,
    /// Specifies the interface on which the event(s) on this System originated.
    #[serde(rename = "$attr:interface", default, skip_serializing_if="Option::is_none")]
    pub interface: Option<String>,
    /// An indication of confidence in whether this System was the true target or attacking host.
    #[serde(rename = "$attr:spoofed", default)]
    pub spoofed: YesNoUnknown,
    /// Indicates whether this System is a virtual or physical device.
    #[serde(rename = "$attr:virtual", default)]
    pub is_virtual: YesNoUnknown,
    /// Describes the ownership of this System relative to the victim in the incident.
    #[serde(rename = "$attr:ownership", default, skip_serializing_if="Option::is_none")]
    pub ownership: Option<SystemOwnership>,
    /// A means by which to extend the ownership attribute.
    #[serde(rename = "$attr:ext-ownership", default, skip_serializing_if="Option::is_none")]
    pub ext_ownership: Option<String>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// A host or network involved in the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Node")]
    pub node: Node,
    /// The intended purpose of the system.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}NodeRole", default, skip_serializing_if="Vec::is_empty")]
    pub node_role: Vec<NodeRole>,
    /// A network service running on the system.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Service", default, skip_serializing_if="Vec::is_empty")]
    pub service: Vec<Service>,
    /// The operating system running on the system.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}OperatingSystem", default, skip_serializing_if="Vec::is_empty")]
    pub operating_system: Vec<Software>,
    /// A counter with which to summarize properties of this host or network.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Counter", default, skip_serializing_if="Vec::is_empty")]
    pub counter: Vec<Counter>,
    /// An asset identifier for the System.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AssetID", default, skip_serializing_if="Vec::is_empty")]
    pub asset_id: Vec<String>,
    /// A free-form text description of the System.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// Mechanism by which to extend the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// Classifies the role the host or network played in the incident.
#[derive(Debug, Serialize, Deserialize)]
pub enum SystemCategory {
    /// The System was the source of the event.
    #[serde(rename = "source")]
    Source,
    /// The System was the target of the event.
    #[serde(rename = "target")]
    Target,
    /// The System was an intermediary in the event.
    #[serde(rename = "intermediate")]
    Intermediate,
    /// The System was a sensor monitoring the event.
    #[serde(rename = "sensor")]
    Sensor,
    /// The System was an infrastructure node of the IODEF document exchange.
    #[serde(rename = "infrastructure")]
    Infrastructure,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// Describes the ownership of this System relative to the victim in the incident.
#[derive(Debug, Serialize, Deserialize)]
pub enum SystemOwnership {
    /// Corporate or enterprise owned.
    #[serde(rename = "organization")]
    Organisation,
    /// Personally owned by an employee or affiliate of the corporation or enterprise.
    #[serde(rename = "personal")]
    Personal,
    /// Owned by a partner of the corporation or enterprise.
    #[serde(rename = "partner")]
    Partner,
    /// Owned by a customer of the corporation or enterprise.
    #[serde(rename = "customer")]
    Customer,
    /// Owned by an entity that has no known relationship with the victim organization.
    #[serde(rename = "no-relationship")]
    NoRelationship,
    /// Ownership is unknown.
    #[serde(rename = "unknown")]
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The Node class identifies a system, asset, or network and its location.
#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    /// The domain (DNS) information associated with this node.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DomainData", default, skip_serializing_if="Vec::is_empty")]
    pub domain_data: Vec<DomainData>,
    /// The hardware, network, or application address of the node.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Address", default, skip_serializing_if="Vec::is_empty")]
    pub address: Vec<Address>,
    /// The hardware, network, or application address of the node.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}PostalAddress", default, skip_serializing_if="Option::is_none")]
    pub postal_address: Option<PostalAddress>,
    /// A free-form text description of the physical location of the node.
    /// This description may provide a more detailed description of where at the address specified by the
    /// PostalAddress class this node is found (e.g., room number, rack number, or slot number in a chassis).
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Location", default, skip_serializing_if="Vec::is_empty")]
    pub location: Vec<MLStringType>,
    /// A counter with which to summarize properties of this host or network.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Counter", default, skip_serializing_if="Vec::is_empty")]
    pub counter: Vec<Counter>,
}

/// The Address class represents a hardware (Layer 2), network (Layer 3), or application (Layer 7) address.
#[derive(Debug, Serialize, Deserialize)]
pub struct Address {
    #[serde(rename = "$value")]
    pub value: String,

    /// The type of address represented.
    #[serde(rename = "$attr:category", default)]
    pub category: AddressCategory,
    /// A means by which to extend the category attribute.
    #[serde(rename = "$attr:ext-category", default, skip_serializing_if="Option::is_none")]
    pub ext_category: Option<String>,
    /// The name of the Virtual LAN to which the address belongs.
    #[serde(rename = "$attr:vlan-name", default, skip_serializing_if="Option::is_none")]
    pub vlan_name: Option<String>,
    /// The number of the Virtual LAN to which the address belongs.
    #[serde(rename = "$attr:vlan-num", default, skip_serializing_if="Option::is_none")]
    pub vlan_num: Option<u32>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,
}

/// The type of address represented.
#[derive(Debug, Serialize, Deserialize)]
pub enum AddressCategory {
    /// Autonomous System Number.
    #[serde(rename = "asn")]
    ASN,
    /// Asynchronous Transfer Mode (ATM) address.
    #[serde(rename = "atm")]
    ATM,
    /// Email address.
    #[serde(rename = "e-mail")]
    Email,
    /// IPv4 host address in dotted-decimal notation (i.e., a.b.c.d).
    #[serde(rename = "ipv4-addr")]
    IPv4Addr,
    /// IPv4 network address in dotted-decimal notation, slash, significant bits (i.e., a.b.c.d/nn).
    #[serde(rename = "ipv4-net")]
    IPv4Net,
    /// A sanitized IPv4 address with significant bits per "ipv4-net" but with the character 'x' replacing any digit(s) in the address or prefix.
    #[serde(rename = "ipv4-net-masked")]
    IPv4NetMasked,
    /// IPv4 network address in dotted-decimal notation, slash, network mask in dotted-decimal notation (i.e., a.b.c.d/w.x.y.z).
    #[serde(rename = "ipv4-net-mask")]
    IPv4NetMask,
    /// IPv6 host address per §4 of RFC5952.
    #[serde(rename = "ipv6-addr")]
    IPv6Addr,
    /// IPv6 network address, slash, prefix per §2.3 of RFC4291.
    #[serde(rename = "ipv6-net")]
    IPv6Net,
    /// A sanitized IPv6 address and prefix per "ipv6-net" but with the character 'x' replacing any
    /// hexadecimal digit(s) in the address or digit(s) in the prefix.
    #[serde(rename = "ipv6-net-masked")]
    IPv6NetMasked,
    /// Media Access Control (MAC) address (i.e. aa:bb:cc:dd:ee:ff).
    #[serde(rename = "mac")]
    MAC,
    /// A URL or URI for a resource.
    #[serde(rename = "site-uri")]
    SiteURI,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

impl Default for AddressCategory {
    fn default() -> Self {
        Self::IPv6Addr
    }
}

/// The NodeRole class describes the function performed by or role of a particular system, asset, or network.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeRole {
    /// Function or role of a node.
    #[serde(rename = "$attr:category")]
    pub category: NodeRoleCategory,
    /// A means by which to extend the category attribute.
    #[serde(rename = "$attr:ext-category", default, skip_serializing_if="Option::is_none")]
    pub ext_category: Option<String>,

    /// A free-form text description of the  role of the system.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

/// Function or role of a node.
#[derive(Debug, Serialize, Deserialize)]
pub enum NodeRoleCategory {
    /// Client computer.
    #[serde(rename = "client")]
    Client,
    /// Client computer on the enterprise network.
    #[serde(rename = "client-enterprise")]
    ClientEnterprise,
    /// Client computer on network of a partner.
    #[serde(rename = "client-partner")]
    ClientPartner,
    /// Client computer remotely connected to the enterprise network.
    #[serde(rename = "client-remote")]
    ClientRemote,
    /// Client computer serving as a kiosk.
    #[serde(rename = "client-kiosk")]
    ClientKiosk,
    /// Mobile device.
    #[serde(rename = "client-mobile")]
    ClientMobile,
    /// Server with internal services.
    #[serde(rename = "server-internal")]
    ServerInternal,
    /// Server with public services.
    #[serde(rename = "server-public")]
    ServerPublic,
    /// WWW server
    #[serde(rename = "www")]
    WWW,
    /// Mail server
    #[serde(rename = "mail")]
    Mail,
    /// Webmail server
    #[serde(rename = "webmail")]
    WebMail,
    /// Messaging server (e.g., NNTP, IRC, IM).
    #[serde(rename = "messaging")]
    Messaging,
    /// Streaming-media server.
    #[serde(rename = "streaming")]
    Streaming,
    /// Voice server (e.g., SIP, H.323).
    #[serde(rename = "voice")]
    Voice,
    /// File server.
    #[serde(rename = "file")]
    File,
    /// FTP server.
    #[serde(rename = "ftp")]
    FTP,
    /// Peer-to-peer node.
    #[serde(rename = "p2p")]
    P2P,
    /// Name server (e.g., DNS, WINS).
    #[serde(rename = "name")]
    Name,
    /// Directory server (e.g., LDAP, finger, whois).
    #[serde(rename = "directory")]
    Directory,
    /// Credential server (e.g., domain controller, Kerberos).
    #[serde(rename = "credential")]
    Credential,
    /// Print server
    #[serde(rename = "print")]
    Print,
    /// Application server
    #[serde(rename = "application")]
    Application,
    /// Database server
    #[serde(rename = "database")]
    Database,
    /// Backup server
    #[serde(rename = "backup")]
    Backup,
    /// DHCP server
    #[serde(rename = "dhcp")]
    DHCP,
    /// Assessment server (e.g., vulnerability scanner, endpoint assessment).
    #[serde(rename = "assessment")]
    Assessment,
    /// Source code control server.
    #[serde(rename = "source-control")]
    SourceControl,
    /// Configuration management server.
    #[serde(rename = "config-management")]
    ConfigManagement,
    /// Security monitoring server (e.g., IDS).
    #[serde(rename = "monitoring")]
    Monitoring,
    /// Infrastructure server (e.g., router, firewall, DHCP).
    #[serde(rename = "infra")]
    Infrastructure,
    /// Firewall
    #[serde(rename = "infra-firewall")]
    InfrastructureFirewall,
    /// Router
    #[serde(rename = "infra-router")]
    InfrastructureRouter,
    /// Switch
    #[serde(rename = "infra-switch")]
    InfrastructureSwitch,
    /// Camera and video system.
    #[serde(rename = "camera")]
    Camera,
    /// Proxy server.
    #[serde(rename = "proxy")]
    Proxy,
    /// Remote access server.
    #[serde(rename = "remote-access")]
    RemoteAccess,
    /// Log server (e.g., syslog).
    #[serde(rename = "log")]
    Log,
    /// Server running virtual machines.
    #[serde(rename = "virtualization")]
    Virtualization,
    /// Point-of-sale device.
    #[serde(rename = "pos")]
    POS,
    /// Supervisory control and data acquisition (SCADA) system.
    #[serde(rename = "scada")]
    SCADA,
    /// Supervisory system for a SCADA.
    #[serde(rename = "scada-supervisory")]
    SCADASupervisory,
    /// Traffic sinkhole destination.
    #[serde(rename = "sinkhole")]
    Sinkhole,
    /// Honeypot server.
    #[serde(rename = "honeypot")]
    Honeypot,
    /// Anonymization server (e.g., Tor node).
    #[serde(rename = "anonymization")]
    Anonymization,
    /// Malicious command and control server.
    #[serde(rename = "c2-server")]
    C2Server,
    /// Server that distributes malware
    #[serde(rename = "malware-distribution")]
    MalwareDistribution,
    /// Server to which exfiltrated content is uploaded.
    #[serde(rename = "drop-server")]
    DropServer,
    /// Intermediary server used to get to a victim.
    #[serde(rename = "hop-point")]
    HopPoint,
    /// A system used in a reflector attack.
    #[serde(rename = "reflector")]
    Reflector,
    /// Site hosting phishing content.
    #[serde(rename = "phishing-site")]
    PhishingSite,
    /// Site hosting spear-phishing content.
    #[serde(rename = "spear-phishing-site")]
    SpearPhishingSite,
    /// Site to recruit.
    #[serde(rename = "recruiting-site")]
    RecruitingSite,
    /// Fraudulent site.
    #[serde(rename = "fraudulent-site")]
    FraudulentSite,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The DomainData class describes a domain name and metadata associated with this domain.
#[derive(Debug, Serialize, Deserialize)]
pub struct DomainData {
    /// Assesses the domain's involvement in the event.
    #[serde(rename = "$attr:system-status")]
    pub system_status: DomainSystemStatus,
    /// A means by which to extend the system-status attribute.
    #[serde(rename = "$attr:ext-system-status", default, skip_serializing_if="Option::is_none")]
    pub ext_system_status: Option<String>,
    /// Categorizes the registry status of the domain at the time the document was generated.
    #[serde(rename = "$attr:domain-status")]
    pub domain_status: DomainStatus,
    /// A means by which to extend the domain-status attribute.
    #[serde(rename = "$attr:ext-domain-status", default, skip_serializing_if="Option::is_none")]
    pub ext_domain_status: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// The domain name of a system.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Name")]
    pub name: String,
    /// A timestamp of when the domain listed in the Name class was resolved.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DateDomainWasChecked", default, skip_serializing_if="Option::is_none")]
    pub checked: Option<DateTime<Utc>>,
    /// A timestamp of when domain listed in the Name class was registered.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RegistrationDate", default, skip_serializing_if="Option::is_none")]
    pub registered: Option<DateTime<Utc>>,
    /// A timestamp of when the domain listed in the Name class is set to expire.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ExpirationDate", default, skip_serializing_if="Option::is_none")]
    pub expiry: Option<DateTime<Utc>>,
    /// Additional DNS records associated with this domain.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RelatedDNS", default, skip_serializing_if="Vec::is_empty")]
    pub related_dns: Vec<Expectation>,
    /// The nameservers identified for the domain listed in the Name class.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Nameservers", default, skip_serializing_if="Vec::is_empty")]
    pub nameservers: Vec<Nameservers>,
    /// Contact information for the domain listed in the Name class supplied by the registrar or through a whois query.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DomainContacts", default, skip_serializing_if="Option::is_none")]
    pub domain_contacts: Option<DomainContacts>,
}

/// The type of address represented.
#[derive(Debug, Serialize, Deserialize)]
pub enum DomainSystemStatus {
    /// This domain was spoofed.
    #[serde(rename = "spoofed")]
    Spoofed,
    /// This domain was operated with fraudulent intentions.
    #[serde(rename = "fraudulent")]
    Fraudulent,
    /// This domain was compromised by a third party.
    #[serde(rename = "innocent-hacked")]
    InnocentHacked,
    /// This domain was deliberately hijacked.
    #[serde(rename = "innocent-hijacked")]
    InnocentHijacked,
    /// No categorization for this domain known.
    #[serde(rename = "Unknown")]
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// Categorizes the registry status of the domain.
#[derive(Debug, Serialize, Deserialize)]
pub enum DomainStatus {
    /// The domain is permanently inactive.
    #[serde(rename = "reservedDelegation")]
    ReservedDelegation,
    /// The domain is in a normal state.
    #[serde(rename = "assignedAndActive")]
    AssignedAndActive,
    /// The domain has an assigned registration, but the delegation is inactive.
    #[serde(rename = "assignedAndInactive")]
    AssignedAndInactive,
    /// The domain is in dispute.
    #[serde(rename = "assignedAndOnHold")]
    AssignedAndOnHold,
    /// The domain is in the process of being purged from the database.
    #[serde(rename = "revoked")]
    Revoked,
    /// The domain is pending a change in authority.
    #[serde(rename = "transferPending")]
    TransferPending,
    /// The domain is on hold by the registry.
    #[serde(rename = "registryLock")]
    RegistryLock,
    /// The domain is on hold by the registrar.
    #[serde(rename = "registrarLock")]
    RegistrarLock,
    /// The domain has a known status, but it is not one of the redefined enumerated values.
    #[serde(rename = "other")]
    Other,
    /// No categorization for this domain known.
    #[serde(rename = "Unknown")]
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The Nameservers class describes the nameservers associated with a given domain.
#[derive(Debug, Serialize, Deserialize)]
pub struct Nameservers {
    /// The domain name of the nameserver.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Server")]
    pub server: String,
    /// The address of the nameserver. The value of the category attribute MUST be either "ipv4-addr" or "ipv6-addr".
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Address")]
    pub addresses: Vec<Address>,
}

/// The DomainContacts class describes the contact information for a given domain provided either
/// by the registrar or through a whois query.
#[derive(Debug, Serialize, Deserialize)]
pub enum DomainContacts {
    /// A domain name already cited in this document or through previous exchange that contains the identical
    /// contact information as the domain name in question.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}SameDomainContact")]
    SameDomainContact(String),
    /// Contact information for the domain.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Contact")]
    Contacts(Vec<Contact>)
}

/// The Service class describes a network service.
/// The service is described by a protocol, port, protocol header field, and application providing or using the service.
#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    /// The IANA-assigned IP protocol number
    #[serde(rename = "$attr:ip-protocol", default, skip_serializing_if="Option::is_none")]
    pub ip_protocol: Option<u8>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// A protocol name.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ServiceName", default, skip_serializing_if="Option::is_none")]
    pub service_name: Option<ServiceName>,
    /// A port number.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Port", default, skip_serializing_if="Option::is_none")]
    pub port: Option<u16>,
    /// A list of port numbers.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Portlist", default, skip_serializing_if="Option::is_none")]
    pub port_list: Option<String>,
    /// A transport-layer (Layer 4) protocol-pecific code field (e.g., ICMP code field).
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ProtoCode", default, skip_serializing_if="Option::is_none")]
    pub proto_code: Option<u32>,
    /// A transport-layer (Layer 4) protocol-pecific type field (e.g., ICMP type field).
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ProtoType", default, skip_serializing_if="Option::is_none")]
    pub proto_type: Option<u32>,
    /// A transport-layer (Layer 4) protocol-specific flag field (e.g., TCP flag field).
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ProtoField", default, skip_serializing_if="Option::is_none")]
    pub proto_field: Option<u32>,
    /// A protocol header.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ApplicationHeader", default, skip_serializing_if="Option::is_none")]
    pub application_header: Option<ApplicationHeader>,
    /// Headers associated with an email message.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailData", default, skip_serializing_if="Option::is_none")]
    pub email_data: Option<EmailData>,
    /// The application acting as either the client or the server for the service.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Application", default, skip_serializing_if="Option::is_none")]
    pub application: Option<Software>,
}

/// The ServiceName class identifies an application protocol.
/// It can be described by referencing an IANA-registered protocol, by referencing a URL, or with free-form text.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceName {
    /// The name of the service per the "Service Name" field of the registry
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IANAService", default, skip_serializing_if="Option::is_none")]
    pub iana_service: Option<String>,
    /// A URL to a resource describing the service.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}URL", default, skip_serializing_if="Vec::is_empty")]
    pub url: Vec<String>,
    /// A free-form text description of the service.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

/// The ApplicationHeader class describes arbitrary fields from a protocol header and its corresponding value.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationHeader {
    /// A field name and value in a protocol header. The name attribute MUST be set to the field name.
    /// The field value MUST be set in the element content.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ApplicationHeaderField", default, skip_serializing_if="Vec::is_empty")]
    pub fields: Vec<ExtensionType>,
}

/// The EmailData class describes headers from an email message and cryptographic hashes and signatures applied to it.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailData {
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,

    /// The value of the "To:" header field in an email.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailTo", default, skip_serializing_if="Vec::is_empty")]
    pub email_to: Vec<String>,
    /// The value of the "From:" header field in an email.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailFrom", default, skip_serializing_if="Option::is_none")]
    pub email_from: Option<String>,
    /// The value of the "Subject:" header field in an email.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailSubject", default, skip_serializing_if="Option::is_none")]
    pub email_subject: Option<String>,
    /// The value of the "X-Mailer:" header field in an email.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailX-Mailer", default, skip_serializing_if="Option::is_none")]
    pub email_xmailer: Option<String>,
    /// The header name and value of an arbitrary header field of the email message
    /// The name attribute MUST be set to the header name.
    /// The header value MUST be set in the element body. The dtype attribute MUST be set to "string".
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailHeaderField", default, skip_serializing_if="Vec::is_empty")]
    pub email_header_fields: Vec<ExtensionType>,
    /// The headers of an email message.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailHeaders", default, skip_serializing_if="Option::is_none")]
    pub email_headers: Option<String>,
    /// The body of an email message.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailBody", default, skip_serializing_if="Option::is_none")]
    pub email_body: Option<String>,
    /// The headers and body of an email message.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}EmailMessage", default, skip_serializing_if="Option::is_none")]
    pub email_message: Option<String>,
    /// Hash(es) associated with this email message.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}HashData", default, skip_serializing_if="Vec::is_empty")]
    pub hash_data: Vec<HashData>,
    /// Signature(s) associated with this email message.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}SignatureData", default, skip_serializing_if="Vec::is_empty")]
    pub signature_data: Vec<SignatureData>,
}

/// The Record class is a container class for log and audit data that provides supportive information about the events in an incident.
/// The source of this data will often be the output of monitoring tools. These logs substantiate the activity described in the document.
#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,

    /// Log or audit data generated by a particular tool.
    /// Separate instances of the RecordData class SHOULD be used for each type of log.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RecordData")]
    pub record_data: Vec<RecordData>,
}

/// The RecordData class describes or references log or audit data from a given type of tool and provides a means to annotate the output.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecordData {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if = "Option::is_none")]
    pub observable_id: Option<String>,

    /// A timestamp of the data found in the RecordItem or URL classes.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}DateTime", default, skip_serializing_if="Option::is_none")]
    pub date_time: Option<DateTime<Utc>>,
    /// A free-form text description of the data provided in the RecordItem or URL classes.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
    /// Identifies the tool used to generate the data in the RecordItem or URL classes.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Application", default, skip_serializing_if="Option::is_none")]
    pub application: Option<Software>,
    /// A search string to precisely find the relevant data in the RecordItem or URL classes.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RecordPattern", default, skip_serializing_if="Vec::is_empty")]
    pub record_pattern: Vec<RecordPattern>,
    /// Log, audit, or forensic data to support the conclusions made during the course of analyzing the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}RecordItem", default, skip_serializing_if="Vec::is_empty")]
    pub record_item: Vec<ExtensionType>,
    /// A URL reference to a log or audit data.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}URL", default, skip_serializing_if="Vec::is_empty")]
    pub url: Vec<String>,
    /// The files involved in the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}FileData", default, skip_serializing_if="Vec::is_empty")]
    pub file_data: Vec<FileData>,
    /// The registry keys that were involved in the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}WindowsRegistryKeysModified", default, skip_serializing_if="Vec::is_empty")]
    pub windows_registry_keys_modified: Vec<WindowsRegistryKeysModified>,
    /// The certificates that were involved in the incident.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}CertificateData", default, skip_serializing_if="Vec::is_empty")]
    pub certificate_data: Vec<CertificateData>,
    /// An extension mechanism for data not explicitly represented in the data model.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
}

/// The RecordPattern class describes where in the log data provided or referenced in the RecordData
/// class relevant information can be found. It provides a way to reference subsets of information,
/// identified by a pattern, in a large log file, audit trail, or forensic data.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecordPattern {
    #[serde(rename = "$value")]
    pub value: String,

    /// Describes the type of pattern being specified in the element content.
    #[serde(rename = "$attr:type", default)]
    pub pattern_type: RecordPatternType,
    /// A means by which to extend the type attribute.
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_pattern_type: Option<String>,
    /// Amount of units (determined by the offsetunit attribute) to seek into the RecordItem data before matching the pattern.
    #[serde(rename = "$attr:offset", default, skip_serializing_if="Option::is_none")]
    pub offset: Option<usize>,
    /// Describes the units of the offset attribute.
    #[serde(rename = "$attr:offsetunit", default)]
    pub offset_unit: RecordPatternOffsetUnit,
    /// A means by which to extend the offsetunit attribute.
    #[serde(rename = "$attr:ext-offsetunit", default, skip_serializing_if="Option::is_none")]
    pub ext_offset_unit: Option<String>,
    /// Number of times to apply the specified pattern.
    #[serde(rename = "$attr:instance", default, skip_serializing_if="Option::is_none")]
    pub instance: Option<usize>,
}

/// Describes the type of pattern being specified in the element content.
#[derive(Debug, Serialize, Deserialize)]
pub enum RecordPatternType {
    /// Regular expression as defined by POSIX Extended Regular Expressions (ERE)
    #[serde(rename="regex")]
    Regex,
    /// Binhex-encoded binary pattern.
    #[serde(rename="binary")]
    Binary,
    /// XML Path (XPath).
    #[serde(rename="xpath")]
    XPath,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

impl Default for RecordPatternType {
    fn default() -> Self {
        Self::Regex
    }
}

/// Describes the units of the offset attribute.
#[derive(Debug, Serialize, Deserialize)]
pub enum RecordPatternOffsetUnit {
    /// Offset is a count of lines.
    #[serde(rename="line")]
    Line,
    /// Offset is a count of bytes.
    #[serde(rename="byte")]
    Byte,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

impl Default for RecordPatternOffsetUnit {
    fn default() -> Self {
        Self::Line
    }
}

/// The WindowsRegistryKeysModified class describes Windows operating system registry keys and the operations that were performed on them.
#[derive(Debug, Serialize, Deserialize)]
pub struct WindowsRegistryKeysModified {
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if = "Option::is_none")]
    pub observable_id: Option<String>,

    /// The Windows registry key.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Key")]
    pub keys: Vec<Key>,
}

/// The Key class describes a Windows operating system registry key name and value pair, as well as the operation performed on it.
#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    /// The type of action taken on the registry key.
    #[serde(rename = "$attr:registryaction", default, skip_serializing_if="Option::is_none")]
    pub registry_action: Option<RegistryAction>,
    /// A means by which to extend the registryaction attribute.
    #[serde(rename = "$attr:ext-registryaction", default, skip_serializing_if="Option::is_none")]
    pub ext_registry_action: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if = "Option::is_none")]
    pub observable_id: Option<String>,

    /// The name of a Windows operating system registry key (e.g., \[HKEY_LOCAL_MACHINE\\Software\\Test\\KeyName\]).
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}KeyName")]
    pub key_name: String,
    /// The value of the registry key identified in he KeyName class encoded per the .reg file format
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}KeyValue", default, skip_serializing_if = "Option::is_none")]
    pub key_value: Option<String>,
}

/// The type of action taken on the registry key.
#[derive(Debug, Serialize, Deserialize)]
pub enum RegistryAction {
    /// Registry key added.
    #[serde(rename = "add-key")]
    AddKey,
    /// Value added to a registry key.
    #[serde(rename = "add-value")]
    AddValue,
    /// Registry key deleted.
    #[serde(rename = "delete-key")]
    DeleteKey,
    /// Value deleted from a registry key.
    #[serde(rename = "delete-value")]
    DeleteValue,
    /// Registry key modified.
    #[serde(rename = "modify-key")]
    ModifyKey,
    /// Value modified from a registry key.
    #[serde(rename = "modify-value")]
    ModifyValue,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue,
}

/// The CertificateData class describes X.509 certificates.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateData {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if = "Option::is_none")]
    pub observable_id: Option<String>,

    /// A description of an X.509 certificate or certificate chain.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Certificate")]
    pub certificates: Vec<Certificate>
}

/// The Certificate class describes a given X.509 certificate or certificate chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate {
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if = "Option::is_none")]
    pub observable_id: Option<String>,

    /// A given X.509 certificate or chain.
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509Data")]
    pub x509_data: xmlsec::proto::ds::X509Data,
    /// A free-form text description explaining the context of this certificate.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Description", default, skip_serializing_if="Vec::is_empty")]
    pub description: Vec<MLStringType>,
}

/// The FileData class describes a file or set of files.
#[derive(Debug, Serialize, Deserialize)]
pub struct FileData {
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if = "Option::is_none")]
    pub observable_id: Option<String>,

    /// A description of a file.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}File")]
    pub files: Vec<File>
}

/// The File class describes a file; its associated metadata; and cryptographic hashes and signatures applied to it.
#[derive(Debug, Serialize, Deserialize)]
pub struct File {
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if = "Option::is_none")]
    pub observable_id: Option<String>,

    /// The name of the file.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}FileName", default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// The size of the file in bytes.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}FileSize", default, skip_serializing_if = "Option::is_none")]
    pub file_size: Option<usize>,
    /// The type of file per the IANA "Media Types" registry
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}FileType", default, skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    /// A URL reference to the file.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}URL", default, skip_serializing_if="Vec::is_empty")]
    pub url: Vec<String>,
    /// Hash(es) associated with this file.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}HashData", default, skip_serializing_if="Option::is_none")]
    pub hash_data: Option<HashData>,
    /// Signature(s) associated with this file.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}SignatureData", default, skip_serializing_if="Option::is_none")]
    pub signature_data: Option<SignatureData>,
    /// The software application or operating system to which this file belongs or by which it can be processed.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AssociatedSoftware", default, skip_serializing_if="Option::is_none")]
    pub associated_software: Option<Software>,
    /// Mechanism by which to extend the data model to describe properties of the file.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}FileProperties", default, skip_serializing_if="Option::is_none")]
    pub file_properties: Vec<ExtensionType>,
}

/// The HashData class describes different types of hashes on a given object (e.g., file, part of a file, email).
#[derive(Debug, Serialize, Deserialize)]
pub struct HashData {
    /// Describes on which part of the object the hash should be applied.
    #[serde(rename = "$attr:scope", default, skip_serializing_if="Option::is_none")]
    pub scope: Option<HashScope>,
    /// A means by which to extend the scope attribute.
    #[serde(rename = "$attr:ext-scope", default, skip_serializing_if="Option::is_none")]
    pub ext_scope: Option<String>,

    /// An identifier that references a subset of the object being hashed.
    /// The semantics of this identifier are specified by the scope attribute.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}HashTargetID", default, skip_serializing_if = "Option::is_none")]
    pub hash_target_id: Option<String>,
    /// The hash of an object.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Hash", default, skip_serializing_if="Vec::is_empty")]
    pub hash: Vec<Hash>,
    /// The fuzzy hash of an object.
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}FuzzyHash", default, skip_serializing_if="Vec::is_empty")]
    pub fuzzy_hash: Vec<FuzzyHash>,
}

/// Describes on which part of the object the hash should be applied.
#[derive(Debug, Serialize, Deserialize)]
pub enum HashScope {
    /// A hash computed over the entire contents of a file.
    #[serde(rename = "file-contents")]
    FileContents,
    /// A hash computed on a given section of a Windows Portable Executable (PE) file.
    /// If set to this value the HashTargetID class MUST identify the section being hashed.
    /// A section is identified by an ordinal number (starting at 1) corresponding to the order in
    /// which the given section header was defined in the Section Table of the PE file header.
    #[serde(rename = "file-pe-section")]
    FilePESection,
    /// A hash computed on the Import Address Table (IAT) of a PE file.
    /// As IAT hashes are often tool dependent, if this value is set, the Application class of
    /// either the Hash or FuzzyHash classes MUST specify the tool used to generate the hash.
    #[serde(rename = "file-pe-iat")]
    FilePEIAT,
    /// A hash computed on a given resource in a PE file.
    /// If set to this value, the HashTargetID class MUST identify the resource being hashed.
    /// A resource is identified by an ordinal number (starting at 1) corresponding to the
    /// order in which the given resource is declared in the Resource Directory of the Data Dictionary in the PE file header.
    #[serde(rename = "file-pe-resource")]
    FilePEResource,
    /// A hash computed on a given object in a Portable Document Format (PDF) file.
    /// If set to this value the HashTargetID class MUST identify the object being hashed.
    /// This object is identified by its offset in the PDF file.
    #[serde(rename = "file-pdf-object")]
    FilePDFObject,
    /// A hash computed over the headers and body of an email message.
    #[serde(rename = "email-hash")]
    EmailHash,
    /// A hash computed over all of the headers of an email message.
    #[serde(rename = "email-headers-hash")]
    EmailHeadersHash,
    /// A hash computed over the body of an email message.
    #[serde(rename = "email-body-hash")]
    EmailBodyHash,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Occurrence {
    /// This assessment describes activity that has occurred.
    #[serde(rename="actual")]
    Actual,
    /// This assessment describes potential activity that might occur.
    #[serde(rename="potential")]
    Potential,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum YesNoUnknown {
    #[serde(rename="yes")]
    Yes,
    #[serde(rename="no")]
    No,
    #[serde(rename="unknown")]
    Unknown,
}

impl Default for YesNoUnknown {
    fn default() -> Self {
        Self::Unknown
    }
}

/// The Confidence class represents an estimate of the validity and
/// accuracy of data expressed in the document. This estimate can be
/// expressed as a category or a numeric calculation.
#[derive(Debug, Serialize, Deserialize)]
pub struct Confidence {
    #[serde(rename = "$value", default, skip_serializing_if="Option::is_none")]
    pub value: Option<f64>,

    /// A qualitative assessment of confidence.
    #[serde(rename = "$attr:rating")]
    pub rating: ConfidenceRating,
    /// A means by which to extend the rating attribute
    #[serde(rename = "$attr:ext-rating", default, skip_serializing_if="Option::is_none")]
    pub ext_rating: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConfidenceRating {
    Low,
    Medium,
    High,
    Numeric,
    Unknown,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

/// The Counter class summarizes multiple occurrences of an event or conveys counts or rates of various features.
#[derive(Debug, Serialize, Deserialize)]
pub struct Counter {
    #[serde(rename = "$value")]
    pub value: f64,

    /// Specifies the type of counter specified in the element content.
    #[serde(rename = "$attr:type")]
    pub counter_type: CounterType,
    /// A means by which to extend the type attribute
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub ext_type: Option<String>,
    /// Specifies the units of the element content.
    #[serde(rename = "$attr:unit")]
    pub counter_unit: CounterUnit,
    /// A means by which to extend the unit attribute
    #[serde(rename = "$attr:ext-unit", default, skip_serializing_if="Option::is_none")]
    pub ext_unit: Option<String>,
    /// A free-form text description of the metric represented by the Counter.
    #[serde(rename = "$attr:meaning", default, skip_serializing_if="Option::is_none")]
    pub meaning: Option<String>,
    /// If present, the Counter class represents a rate.
    /// This attribute specifies a unit of time over which the rate whose units are specified in the unit attribute is being conveyed.
    #[serde(rename = "$attr:duration", default, skip_serializing_if="Option::is_none")]
    pub duration: Option<Duration>,
    /// A means by which to extend the duration attribute
    #[serde(rename = "$attr:ext-unit", default, skip_serializing_if="Option::is_none")]
    pub ext_duration: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CounterType {
    /// The Counter class value is a counter.
    #[serde(rename = "count")]
    Count,
    /// The Counter class value is a peak value.
    #[serde(rename = "peak")]
    Peak,
    /// The Counter class value is an average.
    #[serde(rename = "average")]
    Average,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CounterUnit {
    /// Bytes transferred
    #[serde(rename = "byte")]
    Byte,
    /// Megabits (Mbits) transferred
    #[serde(rename = "mbit")]
    Mbit,
    #[serde(rename = "packet")]
    Packet,
    /// Network flow records
    #[serde(rename = "flow")]
    Flow,
    #[serde(rename = "session")]
    Session,
    /// Notifications generated by another system (e.g., IDS or SIEM system).
    #[serde(rename = "alert")]
    Alert,
    /// Messages (e.g., mail messages).
    #[serde(rename = "message")]
    Message,
    #[serde(rename = "event")]
    Event,
    #[serde(rename = "host")]
    Host,
    #[serde(rename = "site")]
    Site,
    #[serde(rename = "organization")]
    Organisation,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Duration {
    #[serde(rename = "second")]
    Second,
    #[serde(rename = "minute")]
    Minute,
    #[serde(rename = "hour")]
    Hour,
    #[serde(rename = "day")]
    Day,
    #[serde(rename = "month")]
    Month,
    #[serde(rename = "quarter")]
    Quarter,
    #[serde(rename = "year")]
    Year,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MLStringType {
    #[serde(rename = "$value")]
    pub value: String,
    #[serde(rename = "$attr:xml:lang")]
    pub lang: String,
    #[serde(rename = "$attr:translation-id")]
    pub translation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionType {
    #[serde(rename = "$valueRaw")]
    pub value: String,

    #[serde(rename = "$attr:name", default, skip_serializing_if="Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "$attr:dtype")]
    pub dtype: String,
    /// A means by which to extend the dtype attribute.
    #[serde(rename = "$attr:ext-dtype", default, skip_serializing_if="Option::is_none")]
    pub ext_dtype: Option<String>,
    #[serde(rename = "$attr:meaning", default, skip_serializing_if="Option::is_none")]
    pub meaning: Option<String>,
    #[serde(rename = "$attr:formatid", default, skip_serializing_if="Option::is_none")]
    pub format_id: Option<String>,
    /// See `Restriction`
    #[serde(rename = "$attr:restriction", default, skip_serializing_if="Option::is_none")]
    pub restriction: Option<Restriction>,
    /// A means by which to extend the restriction attribute.
    #[serde(rename = "$attr:ext-restriction", default, skip_serializing_if="Option::is_none")]
    pub ext_restriction: Option<String>,
    #[serde(rename = "$attr:observable-id", default, skip_serializing_if="Option::is_none")]
    pub observable_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DType {
    #[serde(rename = "boolean")]
    Boolean,
    #[serde(rename = "byte")]
    Byte,
    #[serde(rename = "bytes")]
    Bytes,
    #[serde(rename = "character")]
    Character,
    #[serde(rename = "date-time")]
    DateTime,
    #[serde(rename = "integer")]
    Integer,
    #[serde(rename = "ntpstamp")]
    NTPStamp,
    #[serde(rename = "portlist")]
    PortList,
    #[serde(rename = "real")]
    Real,
    #[serde(rename = "string")]
    String,
    #[serde(rename = "file")]
    File,
    #[serde(rename = "path")]
    Path,
    #[serde(rename = "frame")]
    Frame,
    #[serde(rename = "packet")]
    Packet,
    #[serde(rename = "ipv4-packet")]
    IPv4Packet,
    #[serde(rename = "ipv6-packet")]
    IPv6Packet,
    #[serde(rename = "url")]
    URL,
    #[serde(rename = "csv")]
    CSV,
    #[serde(rename = "winreg")]
    WinReg,
    #[serde(rename = "xml")]
    XML,
    /// A value used to indicate that this attribute is extended and the actual value is provided using the corresponding ext-* attribute.
    #[serde(rename = "ext-value")]
    ExtValue
}