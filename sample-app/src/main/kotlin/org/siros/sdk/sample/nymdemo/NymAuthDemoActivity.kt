// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.nymdemo

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.siros.sdk.sample.SirosTheme

/**
 * Demo screen for the wallet's circuit_zk (nym_auth) presenter. Self-contained:
 * no login, no backend, no trust. See [NymAuthDemoRunner] for what is real and
 * what is a stand-in.
 */
class NymAuthDemoActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val runner = NymAuthDemoRunner(demoRootKey())
        setContent {
            SirosTheme {
                Surface(Modifier.fillMaxWidth()) { Screen(runner) }
            }
        }
    }

    /** A random per-install demo root, kept in app-private preferences. Not a wallet key. */
    private fun demoRootKey(): ByteArray {
        val prefs = getSharedPreferences("nym_auth_demo", Context.MODE_PRIVATE)
        prefs.getString("root", null)?.let { return android.util.Base64.decode(it, android.util.Base64.NO_WRAP) }
        val key = ByteArray(32).also(SecureRandom()::nextBytes)
        prefs.edit().putString("root", android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP)).apply()
        return key
    }
}

@androidx.compose.runtime.Composable
private fun Screen(runner: NymAuthDemoRunner) {
    var birth by remember { mutableStateOf("1990-05-17") }
    var ge by remember { mutableStateOf("1900-01-01") }
    var le by remember { mutableStateOf("2008-10-14") }
    var verifier by remember { mutableStateOf("x509_san_dns:verifier.example.org") }
    var output by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun go(foreignPsc: Boolean, scenario: NymAuthDemoRunner.Scenario = NymAuthDemoRunner.Scenario.KNOWN_OFFENDER_PSC, wrongSeed: Boolean = false) {
        busy = true
        scope.launch {
            val outcome = withContext(Dispatchers.Default) {
                runner.run(NymAuthDemoRunner.Params(birth, ge, le, verifier, foreignPsc, scenario, wrongSeed))
            }
            output = when (outcome) {
                is NymAuthDemoRunner.Outcome.Presented -> buildString {
                    appendLine("PRESENTED (fake proof)")
                    appendLine("circuit: ${outcome.circuitId}")
                    appendLine("results: ${outcome.decodedHandles}")
                    appendLine("age_check: ${outcome.ageResult}")
                    appendLine("pseudonym:   ${outcome.pseudonymHex}")
                    appendLine("recomputed:  ${outcome.recomputedHex}")
                    appendLine(if (outcome.pseudonymMatches) "pseudonym matches independent recompute: YES" else "pseudonym matches independent recompute: NO  <-- BUG")
                    appendLine("proof: ${outcome.proofAscii}")
                    appendLine()
                    appendLine("vp_token entry (${outcome.token.length} chars):")
                    append(outcome.token)
                }
                NymAuthDemoRunner.Outcome.Refused -> "REFUSED: access_denied (no description, by design)"
                is NymAuthDemoRunner.Outcome.Failed -> "FAILED (unexpected): ${outcome.message}"
            }
            busy = false
        }
    }

    Column(
        Modifier.verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("nym_auth / circuit_zk demo", style = MaterialTheme.typography.titleLarge)
        Text(
            "FAKE PROOF. The issuer is a published demo key, the seed root is a demo value and the " +
                "proof is a dummy. The validator, commitment check, age predicate, pseudonym derivation " +
                "and CBOR encoding are the SDK's real code.",
            color = MaterialTheme.colorScheme.error,
        )
        OutlinedTextField(birth, { birth = it }, label = { Text("birth_date in the credential") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(ge, { ge = it }, label = { Text("age_check ge (not before)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(le, { le = it }, label = { Text("age_check le (not after)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(verifier, { verifier = it }, label = { Text("verifier_id (prefixed: x509_san_dns:<dns name> or semantic_id:...)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        Button({ go(false) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Present") }
        OutlinedButton({ go(true) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Present with a foreign psc (must refuse)") }
        val ssc = NymAuthDemoRunner.Scenario.KNOWN_OFFENDER_SSC
        Button({ go(false, ssc) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Present known-offender-matching-ssc (issuer-delivered secret_seed)") }
        OutlinedButton({ go(false, ssc, wrongSeed = true) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Present ssc with a wrong seed (must refuse)") }
        SelectionContainer { Text(output, style = MaterialTheme.typography.bodySmall) }
    }
}
