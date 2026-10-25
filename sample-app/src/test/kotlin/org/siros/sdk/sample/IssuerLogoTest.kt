// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import coil.compose.AsyncImagePainter.State
import coil.request.ErrorResult
import coil.request.SuccessResult
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.siros.sdk.credentials.logo.DisplayLogo
import org.siros.sdk.credentials.logo.LogoLoad
import org.siros.sdk.credentials.logo.LogoRejection

/** State/logic level behaviour of the issuer-logo badge. */
class IssuerLogoTest {

    @Test
    fun `an accepted https logo is loaded remotely`() {
        assertEquals(
            LogoSource.Remote("https://issuer.example/logo.png"),
            logoSourceFor("https://issuer.example/logo.png"),
        )
    }

    @Test
    fun `rejected logos fall back to the initial`() {
        assertEquals(LogoSource.Fallback, logoSourceFor("http://issuer.example/logo.png"))
        assertEquals(LogoSource.Fallback, logoSourceFor(null))
        assertEquals(LogoSource.Fallback, logoSourceFor("javascript:alert(1)"))
        assertEquals(LogoSource.Fallback, logoSourceFor("data:image/png;base64,@@@"))
        assertEquals(LogoSource.Fallback, logoSourceFor("data:text/html;base64,PGh0bWw+"))
    }

    @Test
    fun `the initial shows while loading and after a failed load, not only when the URL was rejected`() {
        // The bug: an accepted https logo that 404s / is offline / fails to decode left a blank badge.
        assertTrue(showInitialFor(State.Empty))
        assertTrue(showInitialFor(State.Loading(null)))
        assertTrue(showInitialFor(State.Error(null, mockk<ErrorResult>(relaxed = true))))
        assertFalse(showInitialFor(State.Success(mockk(relaxed = true), mockk<SuccessResult>(relaxed = true))))
    }

    @Test
    fun `initial is the first character of the name, uppercased, or empty`() {
        assertEquals("S", logoInitial("  siros"))
        assertEquals("", logoInitial(null))
        assertEquals("", logoInitial("  "))
    }

    @Test
    fun `a fetched logo is drawn, every failure to fetch falls back to the initial`() = runBlocking {
        val png = byteArrayOf(1, 2, 3)
        val ok = resolveLogoSource("https://issuer.example/l.png") { LogoLoad.Loaded(DisplayLogo.Image(png, 1, 1)) }
        assertTrue(ok is LogoSource.Png && ok.bytes.contentEquals(png))
        for (failure in listOf(LogoLoad.Transient("timeout"), LogoLoad.Rejected(LogoRejection.FetchRejected))) {
            assertEquals(LogoSource.Fallback, resolveLogoSource("https://issuer.example/l.png") { failure })
        }
    }

    @Test
    fun `a rejected uri is never fetched`() = runBlocking {
        var fetched = false
        val r = resolveLogoSource("http://issuer.example/l.png") { fetched = true; LogoLoad.Transient("x") }
        assertEquals(LogoSource.Fallback, r)
        assertFalse(fetched)
    }
}
