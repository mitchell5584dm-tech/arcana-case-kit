package com.arcanaforensics.arcalume.ui

import android.app.Application
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.arcanaforensics.arcalume.core.Carve
import com.arcanaforensics.arcalume.core.Case
import com.arcanaforensics.arcalume.core.Entitlements
import com.arcanaforensics.arcalume.core.Exhibit
import com.arcanaforensics.arcalume.core.Finding
import com.arcanaforensics.arcalume.core.Meta
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config

@RunWith(AndroidJUnit4::class)
@Config(sdk = [35], application = Application::class)
class CaseScreenTest {
    @get:Rule val rule = createComposeRule()

    private fun actions(log: MutableList<String>) = CaseActions(
        addPhotos = { log += "photos" }, addFiles = { log += "files" }, saveDetails = { t, _, _, _, _ -> log += "save:$t" },
        edit = { _, t, _, _ -> log += "edit:$t" }, move = { e, d -> log += "move:${e.title}:$d" }, remove = { log += "remove" },
        sort = { log += "sort" }, packet = { log += "packet" }, bundle = { log += "bundle" },
    )

    private fun exhibit(n: Int, cautions: Int = 0) = Exhibit(
        id = "id$n", title = "Item $n", description = "", fileName = "item$n.jpg", sha256 = "ab".repeat(32), size = 2048, addedUtc = "2026-10-10T12:00:00+00:00",
        kind = Carve.Kind.JPEG, created = "2024-01-1${n}T10:00:00", fields = listOf(Meta.Field("Camera", "Pixel 8")),
        findings = List(cautions) { Finding(Finding.Level.WARN, "Saved again after it was taken.") },
    )

    @Test fun emptyCaseExplainsAndOffersWaysIn() {
        val log = mutableListOf<String>()
        rule.setContent { ArcalumeTheme { CaseScreen(Case(), Entitlements.FREE, actions(log)) } }
        rule.onNodeWithText("Build your case file").assertExists()
        rule.onNodeWithText("Add photos or videos").assertHasClickAction().performClick()
        rule.onNodeWithText("Add files").performClick()
        rule.onNodeWithText("Save").performScrollTo().performClick()
        assertEquals(listOf("photos", "files", "save:"), log)
        rule.onNodeWithText("Make exhibit packet (PDF)").assertDoesNotExist()
    }

    @Test fun exhibitsAreNumberedWithCautionsAndReorderable() {
        val log = mutableListOf<String>()
        val case = Case(title = "Smith v. Jones", exhibits = listOf(exhibit(1), exhibit(2, cautions = 2), exhibit(3), exhibit(4)))
        rule.setContent { ArcalumeTheme { CaseScreen(case, Entitlements.FREE, actions(log)) } }
        rule.onNodeWithText("4 exhibits").performScrollTo().assertExists()
        rule.onNodeWithText("Exhibit 2: Item 2").performScrollTo().assertExists()
        rule.onNodeWithText("2 things to be ready to explain").performScrollTo().assertExists()
        rule.onNodeWithContentDescription("Move exhibit 1 up").assertIsNotEnabled()
        rule.onNodeWithContentDescription("Move exhibit 1 down").performScrollTo().performClick()
        rule.onNodeWithText("The free plan prints the first 3 exhibits", substring = true).performScrollTo().assertExists()
        rule.onNodeWithText("Make exhibit packet (PDF)").performScrollTo().performClick()
        rule.onNodeWithText("Make verification bundle (ZIP)").performScrollTo().performClick()
        assertEquals(listOf("move:Item 1:1", "packet", "bundle"), log)
    }

    @Test fun detailsDialogShowsFindingsAndFingerprint() {
        rule.setContent { ArcalumeTheme { ExhibitDialog(0, exhibit(1, cautions = 1), onSave = { _, _, _ -> }, onRemove = {}, onDismiss = {}) } }
        rule.onNodeWithText("Exhibit 1").assertExists()
        rule.onNodeWithContentDescription("Caution: Saved again after it was taken.").assertExists()
        rule.onNodeWithText("ab".repeat(32)).performScrollTo().assertExists()
        rule.onNodeWithText("Remove from case").performScrollTo().performClick()
        rule.onNodeWithText("Yes, remove it").assertExists()
    }
}
