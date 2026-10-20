// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.io.File
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.AgeForm
import org.siros.sdk.credentials.ClaimRef
import org.siros.sdk.credentials.ComparisonOp
import org.siros.sdk.credentials.Condition
import org.siros.sdk.credentials.ValueType
import org.siros.sdk.credentials.ConsentEntry
import org.siros.sdk.credentials.ConsentItem
import org.siros.sdk.credentials.ConsentVerifier
import org.siros.sdk.credentials.CredentialRef
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.credentials.PseudonymScope

/** The SDK-owned consent wording: every locale, every key, and what the text may and may not say. */
class PresentationConsentTextTest {
    private val locales = mapOf("values" to Locale.ENGLISH, "values-sv" to Locale("sv"), "values-fi" to Locale("fi"), "values-el" to Locale("el"), "values-pt" to Locale("pt"))

    private fun strings(dir: String): Map<String, String> {
        val file = File("src/main/res/$dir/strings.xml")
        assertTrue("missing ${file.path}", file.exists())
        val nodes = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file).getElementsByTagName("string")
        return (0 until nodes.length).associate { nodes.item(it).attributes.getNamedItem("name").nodeValue to nodes.item(it).textContent }
    }

    /** The consent string keys, named from the enum's resource: the key of [ConsentString] is its resource entry name. */
    private val keyOf = mapOf(
        ConsentString.TITLE to "siros_consent_title", ConsentString.SHARE to "siros_consent_share", ConsentString.CANCEL to "siros_consent_cancel",
        ConsentString.VERIFIER_PROVE to "siros_consent_verifier_prove", ConsentString.VERIFIER_SHARE to "siros_consent_verifier_share",
        ConsentString.AGE_BETWEEN to "siros_consent_age_between", ConsentString.AGE_AT_LEAST to "siros_consent_age_at_least",
        ConsentString.AGE_AT_MOST to "siros_consent_age_at_most", ConsentString.PSEUDONYM to "siros_consent_pseudonym",
        ConsentString.PSEUDONYM_ISSUER_CAN_LINK to "siros_consent_pseudonym_issuer", ConsentString.FOOTER to "siros_consent_footer",
        ConsentString.CLAIM to "siros_consent_claim", ConsentString.LEGACY_PSEUDONYM to "siros_consent_legacy_pseudonym",
        ConsentString.PREDICATE_EQ to "siros_consent_predicate_eq", ConsentString.PREDICATE_NE to "siros_consent_predicate_ne",
        ConsentString.PREDICATE_LT to "siros_consent_predicate_lt", ConsentString.PREDICATE_LE to "siros_consent_predicate_le",
        ConsentString.PREDICATE_GT to "siros_consent_predicate_gt", ConsentString.PREDICATE_GE to "siros_consent_predicate_ge",
        ConsentString.PREDICATE_IN to "siros_consent_predicate_in",
        ConsentString.PREDICATE_DATE_EQ to "siros_consent_predicate_date_eq", ConsentString.PREDICATE_DATE_NE to "siros_consent_predicate_date_ne",
        ConsentString.PREDICATE_DATE_LT to "siros_consent_predicate_date_lt", ConsentString.PREDICATE_DATE_LE to "siros_consent_predicate_date_le",
        ConsentString.PREDICATE_DATE_GT to "siros_consent_predicate_date_gt", ConsentString.PREDICATE_DATE_GE to "siros_consent_predicate_date_ge",
        ConsentString.PREDICATE_DATE_IN to "siros_consent_predicate_date_in",
    )

    private fun textFor(dir: String) = PresentationConsentText({ key, args ->
        String.format(locales.getValue(dir), strings(dir).getValue(keyOf.getValue(key)), *args)
    }, locales.getValue(dir))

    @Test
    fun everyConsentStringExistsInEveryLocale_withTheSamePlaceholders() {
        assertEquals("a ConsentString has no key in this test", ConsentString.values().toSet(), keyOf.keys)
        val english = strings("values").filterKeys { it.startsWith("siros_consent_") }
        assertEquals(keyOf.values.toSet(), english.keys)
        val placeholders = { t: String -> Regex("%\\d\\$[sd]").findAll(t).map { it.value }.sorted().toList() }
        for (dir in locales.keys) {
            val localised = strings(dir).filterKeys { it.startsWith("siros_consent_") }
            assertEquals("$dir is missing or has an extra consent string", english.keys, localised.keys)
            for ((k, t) in localised) {
                assertFalse("$dir/$k is empty", t.isBlank())
                assertEquals("$dir/$k placeholders differ from the default locale", placeholders(english.getValue(k)), placeholders(t))
                // The trust framework and the verifier_id_type are technical: never user text.
                assertFalse("$dir/$k names the framework", t.contains("framework", ignoreCase = true))
            }
        }
        // The two refusal messages of the consent are in every locale too.
        for (dir in locales.keys) {
            for (k in listOf("siros_dcapi_refused_consent_unavailable", "siros_dcapi_refused_user_declined")) assertTrue("$dir/$k", k in strings(dir))
        }
    }

    private fun age(form: AgeForm, vararg bounds: Pair<String, String>) = ConsentItem.Predicate(
        "age_check", ClaimRef(listOf("birth_date"), null), ValueType.DATE, bounds.map { (op, v) -> Condition(ComparisonOp.ofWire(op)!!, listOf(v)) }, form,
    )

    private fun predicate(claim: ClaimRef, type: ValueType, vararg conditions: Condition, function: String = "x_check") =
        ConsentItem.Predicate(function, claim, type, conditions.toList(), null)

    private val ssc = ConsentItem.Pseudonym("known-offender-matching-ssc", PseudonymScope.PER_VERIFIER, true, false, "rp.example", null)
    private val psc = ConsentItem.Pseudonym("known-offender-matching-psc", PseudonymScope.PER_VERIFIER, false, false, "rp.example", null)

    private fun request(vararg items: ConsentItem, verifierId: String? = "rp.example") = PresentationConsentRequest(
        verifier = ConsentVerifier("Example RP", trustFramework = "etsi-tl", trustIdentifier = "rp.example", verifierId = verifierId, verifierIdType = "x509_san_dns"),
        entries = listOf(ConsentEntry(CredentialRef("Nym", "Example Issuer"), items.toList())),
        requestSigned = true,
        locale = "en",
    )

    @Test
    fun theApprovedEnglishWording_isParameterisedPerItem() {
        val screen = textFor("values").render(
            request(ssc, age(AgeForm.Between("1990-01-01", "2008-10-19", 18, 36), "ge" to "1990-01-01", "le" to "2008-10-19")),
        )
        assertEquals("Example RP is asking you to prove:", screen.header)
        assertEquals(
            listOf(
                "A pseudonym for Example RP is shared. You get the same pseudonym every time you visit this service, and a different one at every other service. " +
                    "The service that issued your credential can work out who this pseudonym belongs to.",
                "You were born between January 1, 1990 and October 19, 2008 (about 18–36 years old). Your exact birth date is not shared.",
            ),
            screen.entries.single().lines,
        )
        assertEquals("No other personal data is shared.", screen.footer)
        assertEquals("Nym", screen.entries.single().credentialName)
        assertEquals("Example Issuer", screen.entries.single().issuerName)
        assertEquals("You are at least 18 years old. Your exact birth date is not shared.", textFor("values").render(request(age(AgeForm.AtLeast(18), "le" to "2008-10-19"))).entries.single().lines.single())
        assertEquals("You are at most 26 years old. Your exact birth date is not shared.", textFor("values").render(request(age(AgeForm.AtMost(26), "ge" to "2000-01-01"))).entries.single().lines.single())
    }

    @Test
    fun theIssuerLinkabilitySentence_isThereExactlyWhenTheIssuerCanRemapThePseudonym() {
        for (dir in locales.keys) {
            val t = textFor(dir)
            val remappable = t.render(request(ssc)).entries.single().lines.single()
            val plain = t.render(request(psc)).entries.single().lines.single()
            assertTrue("$dir: the issuer sentence is extra text", remappable.length > plain.length)
            assertTrue("$dir: the plain pseudonym text is a prefix of the remappable one", remappable.startsWith(plain))
        }
    }

    @Test
    fun everyLocaleSaysTheVerifierLineWithTheNameAndNothingTechnical() {
        val expected = mapOf(
            "values" to "Example RP is asking you to prove:", "values-sv" to "Example RP ber dig bevisa:",
            "values-fi" to "Example RP pyytää sinua todistamaan:", "values-el" to "Η υπηρεσία Example RP σας ζητά να αποδείξετε:",
            "values-pt" to "Example RP pede-lhe que prove:",
        )
        for ((dir, line) in expected) {
            val screen = textFor(dir).render(request(ssc, age(AgeForm.AtLeast(18), "le" to "2008-10-19")))
            assertEquals(dir, line, screen.header)
            // Nothing the dialog shows names the trust framework or the verifier_id_type.
            val all = listOf(screen.title, screen.header, screen.footer, screen.shareLabel, screen.cancelLabel) + screen.entries.flatMap { it.lines }
            for (t in all) {
                assertFalse("$dir: $t", t.contains("etsi-tl") || t.contains("x509_san_dns") || t.contains("semantic"))
            }
        }
    }

    @Test
    fun theVerifierIdIsADetailLine_verbatimAndShortenedOnlyForDisplay() {
        val did = "did:web:verifier.example.org:very:long:path:segment:identifying:this:verifier"
        val detail = textFor("values").render(request(ssc, verifierId = did)).verifierDetail!!
        assertEquals(did, detail.full)
        assertEquals(did.take(18) + "…" + did.takeLast(18), detail.shortened)
        assertEquals(null, textFor("values").render(request(age(AgeForm.AtLeast(18), "le" to "2008-10-19"), verifierId = null)).verifierDetail)
    }

    @Test
    fun verifierIdShortening_followsTheSharedVectors() {
        val f = File("../../spec/circuit-zk-consent-vectors.json")
        val cases = Json.parseToJsonElement(f.readText()).jsonObject["verifier_id_shortening"]!!.jsonArray
        assertTrue(cases.size >= 5)
        for (c in cases) {
            val o = c.jsonObject
            assertEquals(o["display"]!!.jsonPrimitive.content, PresentationConsentText.shortenMiddle(o["id"]!!.jsonPrimitive.content))
        }
    }

    @Test
    fun aLegacyDisclosure_isADisclosureScreen_notThePickersNoPersonalDataText() {
        val screen = textFor("values").render(request(ConsentItem.Claim("family_name"), ConsentItem.LegacyPseudonym("ctx")))
        assertEquals("Example RP is asking you to share:", screen.header)
        assertEquals(listOf("The value of “family_name” from your credential is shared.", "A pseudonym is shared with Example RP."), screen.entries.single().lines)
        val picker = strings("values").getValue("siros_dcapi_zk_proof_detail")
        assertTrue(screen.entries.single().lines.none { it.contains("No personal data is shared") })
        assertFalse(picker == screen.footer)
    }

    @Test
    fun aPseudonymScopeTheWordingDoesNotCover_failsInsteadOfBeingOmitted() {
        val xsite = ConsentItem.Pseudonym("user-managed-pseudonym-xsite-ssc", PseudonymScope.CROSS_SITE, true, true, null, null)
        assertThrows(IllegalArgumentException::class.java) { textFor("values").render(request(xsite)) }
        val withContext = ConsentItem.Pseudonym("account-recovery-ssc", PseudonymScope.PER_VERIFIER_CONTEXT, true, false, "rp.example", "acct")
        assertThrows(IllegalArgumentException::class.java) { textFor("values").render(request(withContext)) }
    }

    @Test
    fun aGenericPredicate_saysWhatIsProved_neverReassuresAboutTheValue_inEveryLocale() {
        val score = ClaimRef(listOf("score"), "Credit score")
        val en = textFor("values")
        fun lines(item: ConsentItem) = en.render(request(item)).entries.single().lines
        assertEquals(
            listOf("Credit score is at least 10.", "Credit score is at most 20."),
            lines(predicate(score, ValueType.NUMBER, Condition(ComparisonOp.GE, listOf("10")), Condition(ComparisonOp.LE, listOf("20")))),
        )
        assertEquals(
            listOf("Country is one of: SE, FI."),
            lines(predicate(ClaimRef(listOf("country"), "Country"), ValueType.STRING, Condition(ComparisonOp.IN, listOf("SE", "FI")))),
        )
        // No label: the path is the fallback, never an invented name.
        // A proof of `== SE` (or a singleton membership, or a boolean equality) reveals the value: the text must not claim it is not shared.
        assertEquals(listOf("address.country is SE."), lines(predicate(ClaimRef(listOf("address", "country"), null), ValueType.STRING, Condition(ComparisonOp.EQ, listOf("SE")))))
        assertEquals(listOf("Country is one of: SE."), lines(predicate(ClaimRef(listOf("country"), "Country"), ValueType.STRING, Condition(ComparisonOp.IN, listOf("SE")))))
        // A date operand is written the way the locale writes dates; a date claim that is not a birth date is not an age.
        assertEquals(
            "Issue date is on or after January 1, 2020.",
            lines(predicate(ClaimRef(listOf("issue_date"), "Issue date"), ValueType.DATE, Condition(ComparisonOp.GE, listOf("2020-01-01")))).first(),
        )
        // Every operator has its own sentence in every locale, with the claim and the operand filled in and nothing left over.
        for (dir in locales.keys) {
            val t = textFor(dir)
            for (op in ComparisonOp.values()) {
                val operand = if (op == ComparisonOp.IN) listOf("A", "B") else listOf("A")
                val screen = t.render(request(predicate(ClaimRef(listOf("c"), "CLAIMLABEL"), ValueType.STRING, Condition(op, operand))))
                val sentence = screen.entries.single().lines.first()
                assertTrue("$dir $op: $sentence", sentence.contains("CLAIMLABEL") && sentence.contains("A") && !sentence.contains("%"))
                assertEquals("$dir $op: one sentence per condition, no reassurance", 1, screen.entries.single().lines.size)
            }
        }
    }

    @Test
    fun aHostRendererForAFunction_takesPrecedenceOverTheGenericWording() {
        val t = PresentationConsentText({ _, _ -> "generic" }, Locale.ENGLISH, mapOf("x_check" to { _: ConsentItem.Predicate -> listOf("custom") }))
        val item = predicate(ClaimRef(listOf("c"), null), ValueType.STRING, Condition(ComparisonOp.EQ, listOf("A")))
        assertEquals(listOf("custom"), t.render(request(item)).entries.single().lines)
        assertEquals(listOf("generic"), t.render(request(item.copy(functionId = "other"))).entries.single().lines)
    }

    @Test
    fun aDateClaim_usesTheDateOperatorSentences_aNumberKeepsTheGenericOnes() {
        val en = textFor("values")
        fun lines(type: ValueType, op: ComparisonOp, vararg v: String) =
            en.render(request(predicate(ClaimRef(listOf("d"), "Issue date"), type, Condition(op, v.toList())))).entries.single().lines.first()
        assertEquals("Issue date is on March 1, 2024.", lines(ValueType.DATE, ComparisonOp.EQ, "2024-03-01"))
        assertEquals("Issue date is not on March 1, 2024.", lines(ValueType.DATE, ComparisonOp.NE, "2024-03-01"))
        assertEquals("Issue date is before March 1, 2024.", lines(ValueType.DATE, ComparisonOp.LT, "2024-03-01"))
        assertEquals("Issue date is on or before March 1, 2024.", lines(ValueType.DATE, ComparisonOp.LE, "2024-03-01"))
        assertEquals("Issue date is after March 1, 2024.", lines(ValueType.DATE, ComparisonOp.GT, "2024-03-01"))
        assertEquals("Issue date is on or after March 1, 2024.", lines(ValueType.DATE, ComparisonOp.GE, "2024-03-01"))
        assertEquals("Issue date is one of the dates: March 1, 2024, April 1, 2024.", lines(ValueType.DATE, ComparisonOp.IN, "2024-03-01", "2024-04-01"))
        // The same operators on a number keep the generic wording.
        assertEquals("Issue date is at least 10.", lines(ValueType.NUMBER, ComparisonOp.GE, "10"))
        assertEquals("Issue date is greater than 10.", lines(ValueType.NUMBER, ComparisonOp.GT, "10"))
        // The age specialisation still wins for a function declared as an age.
        val age = predicate(ClaimRef(listOf("birth_date"), null), ValueType.DATE, Condition(ComparisonOp.LE, listOf("2008-10-19")), function = "age_check")
            .copy(age = AgeForm.AtLeast(18))
        assertEquals("You are at least 18 years old. Your exact birth date is not shared.", en.render(request(age)).entries.single().lines.single())
        // In every locale each date operator has its own sentence, different from the generic one for the same operator.
        for (dir in locales.keys) {
            val t = textFor(dir)
            for (op in ComparisonOp.values()) {
                val operand = if (op == ComparisonOp.IN) listOf("2024-03-01", "2024-04-01") else listOf("2024-03-01")
                val date = t.render(request(predicate(ClaimRef(listOf("d"), "CLAIMLABEL"), ValueType.DATE, Condition(op, operand)))).entries.single().lines.first()
                val generic = t.render(request(predicate(ClaimRef(listOf("d"), "CLAIMLABEL"), ValueType.STRING, Condition(op, listOf("X"))))).entries.single().lines.first()
                assertTrue("$dir $op: $date", date.contains("CLAIMLABEL") && !date.contains("%") && !date.contains("2024-03-01"))
                assertTrue("$dir $op: the date sentence is not the generic one: $date", date.replace(Regex("\\S*2024\\S*|\\d+"), "").trim() != generic.replace("X", "").trim())
            }
        }
    }
}
