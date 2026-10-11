package com.arcanaforensics.arcalume.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.arcanaforensics.arcalume.R
import com.arcanaforensics.arcalume.core.Case
import com.arcanaforensics.arcalume.core.Entitlements
import com.arcanaforensics.arcalume.core.Exhibit
import com.arcanaforensics.arcalume.core.Finding

class CaseActions(
    val addPhotos: () -> Unit,
    val addFiles: () -> Unit,
    val saveDetails: (title: String, number: String, court: String, party: String, prefix: String) -> Unit,
    val edit: (Exhibit, String, String, String) -> Unit,
    val move: (Exhibit, Int) -> Unit,
    val remove: (Exhibit) -> Unit,
    val sort: () -> Unit,
    val packet: () -> Unit,
    val bundle: () -> Unit,
)

/**
 * The case: its details, its numbered exhibits with what each file's metadata shows,
 * and the two outputs, the printable exhibit packet and the verification bundle.
 */
@Composable
fun CaseScreen(case: Case, ent: Entitlements, actions: CaseActions, modifier: Modifier = Modifier) {
    var editing by remember { mutableStateOf<Exhibit?>(null) }
    Column(modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        if (case.exhibits.isEmpty()) {
            Section(stringResource(R.string.case_empty_title)) {
                Text(stringResource(R.string.case_empty_body), style = MaterialTheme.typography.bodyLarge)
            }
        }

        Section(stringResource(R.string.case_add_heading)) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = actions.addPhotos, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_add_photos)) }
                OutlinedButton(onClick = actions.addFiles, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_add_files)) }
            }
            Text(stringResource(R.string.case_add_help), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Collapsible(stringResource(R.string.case_chat_help_title)) {
                Text(stringResource(R.string.case_chat_help_whatsapp), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.case_chat_help_sms), style = MaterialTheme.typography.bodyMedium)
            }
        }

        DetailsSection(case, actions)

        if (case.exhibits.isNotEmpty()) {
            Section(pluralStringResource(R.plurals.case_exhibits_heading, case.exhibits.size, case.exhibits.size)) {
                OutlinedButton(onClick = actions.sort, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_sort)) }
                case.exhibits.forEachIndexed { i, e ->
                    if (i > 0) HorizontalDivider()
                    ExhibitRow(i, e, first = i == 0, last = i == case.exhibits.lastIndex, onEdit = { editing = e }, actions = actions)
                }
            }

            Section(stringResource(R.string.case_output_heading)) {
                Text(stringResource(R.string.case_output_body), style = MaterialTheme.typography.bodyMedium)
                if (!ent.packet && case.exhibits.size > Entitlements.FREE_PACKET_EXHIBITS) {
                    Text(stringResource(R.string.case_free_limit, Entitlements.FREE_PACKET_EXHIBITS), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                }
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = actions.packet, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_build_packet)) }
                    OutlinedButton(onClick = actions.bundle, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_build_bundle)) }
                }
                Text(stringResource(R.string.case_not_legal_advice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Text(stringResource(R.string.privacy_line), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    editing?.let { e ->
        ExhibitDialog(case.exhibits.indexOfFirst { it.id == e.id }, e,
            onSave = { t, d, date -> editing = null; actions.edit(e, t, d, date) },
            onRemove = { editing = null; actions.remove(e) },
            onDismiss = { editing = null })
    }
}

@Composable
private fun DetailsSection(case: Case, actions: CaseActions) {
    Collapsible(stringResource(R.string.case_details_heading), startOpen = case.exhibits.isEmpty() && case.title.isBlank()) {
        var title by rememberSaveable(case.title) { mutableStateOf(case.title) }
        var number by rememberSaveable(case.number) { mutableStateOf(case.number) }
        var court by rememberSaveable(case.court) { mutableStateOf(case.court) }
        var party by rememberSaveable(case.party) { mutableStateOf(case.party) }
        var prefix by rememberSaveable(case.stampPrefix) { mutableStateOf(case.stampPrefix) }
        OutlinedTextField(title, { title = it.take(200) }, label = { Text(stringResource(R.string.case_title)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(number, { number = it.take(80) }, label = { Text(stringResource(R.string.case_number)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(court, { court = it.take(200) }, label = { Text(stringResource(R.string.case_court)) }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(party, { party = it.take(120) }, label = { Text(stringResource(R.string.case_party)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(prefix, { prefix = it.uppercase().filter(Char::isLetterOrDigit).take(12) }, label = { Text(stringResource(R.string.case_prefix)) },
            supportingText = { Text(stringResource(R.string.case_prefix_help, Case(title = title, stampPrefix = prefix).prefix)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Button(onClick = { actions.saveDetails(title, number, court, party, prefix) }, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_save)) }
    }
}

@Composable
private fun ExhibitRow(i: Int, e: Exhibit, first: Boolean, last: Boolean, onEdit: () -> Unit, actions: CaseActions) {
    val cautions = e.findings.count { it.level == Finding.Level.WARN }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(R.string.case_exhibit_label, i + 1, e.title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Text(
            listOfNotNull(e.kind.label, e.when_.takeIf { it.isNotBlank() }?.replace('T', ' ')?.take(16), humanBytes(e.size)).joinToString(" · "),
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (cautions > 0) Text(pluralStringResource(R.plurals.case_cautions, cautions, cautions), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            OutlinedButton(onClick = onEdit, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_details_button)) }
            val up = stringResource(R.string.case_move_up, i + 1)
            val down = stringResource(R.string.case_move_down, i + 1)
            IconButton(onClick = { actions.move(e, -1) }, enabled = !first, modifier = Modifier.semantics { contentDescription = up }) { Icon(Icons.Filled.ArrowUpward, contentDescription = null) }
            IconButton(onClick = { actions.move(e, 1) }, enabled = !last, modifier = Modifier.semantics { contentDescription = down }) { Icon(Icons.Filled.ArrowDownward, contentDescription = null) }
        }
    }
}

@Composable
fun ExhibitDialog(index: Int, e: Exhibit, onSave: (String, String, String) -> Unit, onRemove: () -> Unit, onDismiss: () -> Unit) {
    var title by rememberSaveable(e.id) { mutableStateOf(e.title) }
    var description by rememberSaveable(e.id) { mutableStateOf(e.description) }
    var date by rememberSaveable(e.id) { mutableStateOf(e.eventDate) }
    var confirmRemove by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.case_exhibit_number, index + 1)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(title, { title = it.take(160) }, label = { Text(stringResource(R.string.case_exhibit_title)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(description, { description = it.take(2000) }, label = { Text(stringResource(R.string.case_exhibit_description)) }, minLines = 2, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(date, { date = it.take(40) }, label = { Text(stringResource(R.string.case_exhibit_date)) },
                    supportingText = { Text(stringResource(R.string.case_exhibit_date_help)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                FindingsCard(e.findings)
                Heading(stringResource(R.string.case_file_facts))
                for (f in e.fields) Text("${f.label}: ${f.value}", style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.case_fingerprint), style = MaterialTheme.typography.labelLarge)
                SelectionContainer { Mono(e.sha256) }
                if (confirmRemove) {
                    Text(stringResource(R.string.case_remove_confirm), color = MaterialTheme.colorScheme.error)
                    TextButton(onClick = onRemove, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_remove_yes)) }
                } else {
                    TextButton(onClick = { confirmRemove = true }, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_remove)) }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onSave(title, description, date) }, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.case_save)) } },
        dismissButton = { TextButton(onClick = onDismiss, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.cancel)) } },
    )
}
