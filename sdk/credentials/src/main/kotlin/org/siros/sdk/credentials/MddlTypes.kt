// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.Serializable

/**
 * MDDL (mso_mdoc) schema type: the mdoc analogue of [Vctm], mirroring
 * `sirosfoundation/vc`'s `pkg/mdoc/schema.go` `MDDLSchema` field-for-field.
 * Drives mdoc issuance server-side and, here, gives the wallet a uniform way
 * to get display labels/claim metadata for mdoc credentials regardless of
 * format - the same role VCTM plays for SD-JWT.
 */
@Serializable
data class MddlSchema(
    val format: String,
    val doctype: String,
    val display: List<MddlDisplay>? = null,
    val claims: Map<String, Map<String, MddlClaimMeta>>? = null,
    /** See [Vctm.requiredKeyStorage] - same field, same semantics, mdoc side. */
    @kotlinx.serialization.SerialName("attestation_los") val requiredKeyStorage: String? = null,
)

/** Localized display info for an MDDL schema, mirroring `MDDLSchema.Display`. */
@Serializable
data class MddlDisplay(
    val locale: String,
    val name: String,
    val description: String? = null,
    val logo: MddlLogo? = null,
    @kotlinx.serialization.SerialName("background_color") val backgroundColor: String? = null,
    @kotlinx.serialization.SerialName("text_color") val textColor: String? = null,
    /** SVG rendering info, mirroring `DisplayProperties.Rendering`. */
    val rendering: MddlRendering? = null,
)

@Serializable
data class MddlLogo(
    val uri: String? = null,
    @kotlinx.serialization.SerialName("alt_text") val altText: String? = null,
)

/**
 * SVG-based rendering information for an MDDL display entry, mirroring
 * `mdoc.Rendering` (`pkg/mdoc/schema.go`). mdoc has no "simple" rendering
 * sub-object to mirror VCTM's [VctmRendering.simple] - logo/colors already
 * live directly on [MddlDisplay].
 */
@Serializable
data class MddlRendering(
    @kotlinx.serialization.SerialName("svg_templates") val svgTemplates: List<MddlSvgTemplate>? = null,
)

@Serializable
data class MddlSvgTemplate(
    val uri: String,
    val properties: MddlSvgProperties? = null,
)

@Serializable
data class MddlSvgProperties(
    val orientation: String? = null,
    @kotlinx.serialization.SerialName("color_scheme") val colorScheme: String? = null,
    val contrast: String? = null,
)

/**
 * Metadata for a single mdoc data element within a namespace, mirroring
 * `ClaimMetadata` in `pkg/mdoc/schema.go`. `elements` describes nested
 * item/field shape for container (`array`/`map`) claims like
 * `driving_privileges`.
 */
@Serializable
data class MddlClaimMeta(
    val display: List<MddlClaimDisplay>? = null,
    val mandatory: Boolean = false,
    @kotlinx.serialization.SerialName("value_type") val valueType: String? = null,
    val elements: Map<String, MddlClaimMeta>? = null,
    /** SVG template placeholder ID this claim fills, if any. */
    @kotlinx.serialization.SerialName("svg_id") val svgId: String? = null,
)

@Serializable
data class MddlClaimDisplay(
    val locale: String,
    val name: String,
)
