// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.idv.facetec

import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.URLClassLoader
import java.util.zip.ZipFile

/**
 * Checks [FaceTecApi]'s reflection against a **real** FaceTec 10 AAR rather than the test
 * doubles, so a FaceTec release that renames something the SDK calls fails here.
 *
 * FaceTec distributes the AAR privately, so this runs only where one is available: the AAR at
 * `FACETEC_SDK_AAR`, or else the newest `com.facetec:facetec-sdk:10.*` in the local Gradle cache
 * (where it lands once any app depending on it has been built). Elsewhere, e.g. in CI, it is
 * skipped.
 */
class FaceTec10ApiContractTest {
    @Test
    fun `every FaceTec 10 class and method the SDK calls exists in the real AAR`() {
        val aar = findFaceTec10Aar()
        assumeTrue("no FaceTec 10 AAR available; set FACETEC_SDK_AAR to run this check", aar != null)

        val classesJar = extractClassesJar(aar!!)

        val faceTec = FaceTecFirstClassLoader(classesJar, FaceTec10ApiContractTest::class.java.classLoader!!)
        // The AAR's own classes, not the same-named test doubles, are the ones checked.
        assertSame(faceTec, Class.forName(FaceTecApi.SDK, false, faceTec).classLoader)

        assertNull("against ${aar.name}", FaceTecApi(faceTec).missingApi())
    }

    @Test
    fun `the FaceTec 9 classes the deprecated FaceTecCaptureDelegate needs are gone from FaceTec 10`() {
        val aar = findFaceTec10Aar()
        assumeTrue("no FaceTec 10 AAR available; set FACETEC_SDK_AAR to run this check", aar != null)
        val faceTec = FaceTecFirstClassLoader(extractClassesJar(aar!!), FaceTec10ApiContractTest::class.java.classLoader!!)

        for (name in listOf("FaceTecSession", "FaceTecFaceScanProcessor", "FaceTecIDScanSession", "FaceTecIDScanProcessor")) {
            assertTrue(name, runCatching { Class.forName("com.facetec.sdk.$name", false, faceTec) }.isFailure)
        }
    }

    private fun extractClassesJar(aar: File): File {
        val classesJar = File.createTempFile("facetec-classes", ".jar").apply { deleteOnExit() }
        ZipFile(aar).use { zip ->
            zip.getInputStream(zip.getEntry("classes.jar")).use { input ->
                classesJar.outputStream().use { input.copyTo(it) }
            }
        }
        return classesJar
    }

    private fun findFaceTec10Aar(): File? {
        System.getenv("FACETEC_SDK_AAR")?.let { path -> return File(path).takeIf { it.isFile } }

        val cached = File(System.getProperty("user.home"), ".gradle/caches/modules-2/files-2.1/com.facetec/facetec-sdk")
        return cached.listFiles { dir -> dir.name.startsWith("10.") }
            ?.maxWithOrNull(compareBy<File, String>(VERSION_ORDER) { it.name })
            ?.walkTopDown()
            ?.firstOrNull { it.isFile && it.extension == "aar" }
    }

    /**
     * Loads `com.facetec.*` from the real AAR's classes before the test doubles in
     * `src/test/java` (which share their names); everything else, e.g. android.jar, comes from
     * the test class path.
     */
    private class FaceTecFirstClassLoader(jar: File, parent: ClassLoader) : URLClassLoader(arrayOf(jar.toURI().toURL()), parent) {
        override fun loadClass(name: String, resolve: Boolean): Class<*> {
            if (!name.startsWith("com.facetec.")) return super.loadClass(name, resolve)
            synchronized(this) {
                return findLoadedClass(name) ?: findClass(name)
            }
        }
    }

    private companion object {
        /** Orders "10.1.17" after "10.1.4". */
        val VERSION_ORDER = Comparator<String> { a, b ->
            val x = a.split('.').map { it.toIntOrNull() ?: 0 }
            val y = b.split('.').map { it.toIntOrNull() ?: 0 }
            (0 until maxOf(x.size, y.size)).asSequence()
                .map { (x.getOrElse(it) { 0 }).compareTo(y.getOrElse(it) { 0 }) }
                .firstOrNull { it != 0 } ?: 0
        }
    }
}
