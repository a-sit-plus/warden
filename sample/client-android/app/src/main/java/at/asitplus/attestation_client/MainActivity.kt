package at.asitplus.attestation_client

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat.startActivity
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import at.asitplus.attestation.AttestationResponse
import at.asitplus.attestation_client.ui.theme.AttestationClientTheme
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.KeyStore
import java.util.*


val json = Json { prettyPrint = true }
val client = AttestationClient()
val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "certs")


class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AttestationClientTheme {

                // A surface container using the 'background' color from the theme
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {


                    Attestation()


                }
            }
        }
    }
}

@SuppressLint("CoroutineCreationDuringComposition")
@Composable
fun Attestation() {

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val dataStore = context.dataStore

    var host by remember { mutableStateOf("http://192.168.178.33") }

    scope.launch {
        dataStore.data.map { certs ->
            certs[stringPreferencesKey("last_host")]
        }.firstOrNull()?.let {
            host = it
        }
    }

    var log by remember { mutableStateOf("") }


    Column(modifier = Modifier.fillMaxSize().padding(4.dp)) {

        Text("Attestation Demo", fontSize = 30.sp)

        Spacer(Modifier.size(16.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Host:"); Spacer(Modifier.size(8.dp))
            TextField(host,
                modifier = Modifier.fillMaxWidth(), onValueChange = {
                    host = it.lowercase().trim()
                    scope.launch {
                        dataStore.edit { certs ->
                            certs[stringPreferencesKey("last_host")] = it
                        }
                    }
                })
        }

        Spacer(Modifier.size(16.dp))

        Row(modifier = Modifier.fillMaxWidth()) {

            Button(
                modifier = Modifier.fillMaxWidth(0.4f),
                onClick = {
                    scope.launch {
                        System.err.println("trying $host")
                        client.startBinding(host).fold(onFailure = {
                            log = "Could not fetch challenge:\n${it.message}"
                        },
                            onSuccess = {
                                log = "Received Challenge: ${json.encodeToString(it)}"
                                val resp = client.createBinding(host, it.challenge).fold(onFailure = {
                                    log += "Could not create binding:\n${it.message}"
                                },
                                    onSuccess = { resp ->
                                        if (resp is AttestationResponse.Success) {
                                            log += "\n\nGot Binding (${resp.certificateChain.first().subjectDN.name})."
                                            KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
                                                val chain = stringPreferencesKey(host)
                                                dataStore.edit { certs ->
                                                    certs[chain] = Json.encodeToString(resp)
                                                }
                                            }
                                        }
                                        log += "\n\nReceived Binding Response: ${json.encodeToString(resp)}"
                                    })
                            })
                    }

                }) {
                Text(text = "Create Binding")
            }

            Spacer(Modifier.size(16.dp))

            Button(
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.secondary,
                    contentColor = MaterialTheme.colorScheme.onSecondary
                ),
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    client.purge(host)
                    scope.launch {
                        val chain = stringPreferencesKey(host)
                        dataStore.edit { certs ->
                            certs.remove(chain)
                        }
                    }
                    log = "Removed credentials for $host"

                }) {
                Text(text = "Delete credentials for host")
            }

        }
        Button(
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                scope.launch {
                    val certs =
                        dataStore.data.map { certs ->
                            certs[stringPreferencesKey(host)]
                        }.firstOrNull()?.let {
                            json.decodeFromString<AttestationResponse.Success>(it).certificateChain
                        }

                    log = ""
                    if (certs == null)
                        log += "warning! no cert found for $host!\ntrying to access it without authenticating…\n"
                    else
                        log = "Accessing protected resource\n"
                    val response = client.accessProtected(host, certs).fold(onFailure = {
                        log += "\nCould not access protected resource: ${it.message}"
                    },
                        onSuccess = { response ->
                            log += "\nReceived response: ${response.status}"
                            log += "\n\n${response.bodyAsText()}"
                        })
                }

            }) {
            Text(text = "Access Protected Resource")
        }

        Spacer(Modifier.size(16.dp))

        Row {
            Button(
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    contentColor = MaterialTheme.colorScheme.onTertiaryContainer
                ),
                modifier = Modifier.fillMaxWidth(0.4f),
                onClick = {
                    scope.launch {
                        val certs =
                            dataStore.data.map { certs ->
                                certs[stringPreferencesKey(host)]
                            }.firstOrNull()?.let {
                                json.decodeFromString<AttestationResponse.Success>(it).certificateChain
                            }
                        if (certs != null) {
                            log = "Binding certificate chain for $host\n(issued to ${
                                certs.first().subjectDN.name.substring(3)
                            }):\n"
                            certs.forEachIndexed { i, certificate -> log += "\nCertificate ${i + 1}:\n$certificate\n" }
                        } else log = "No binding present for\n$host"

                        log += "\n\nBindings are available for the following hosts:"
                        val hosts = dataStore.data.map {
                            it.asMap().filterNot { (k, _) -> k.name == "last_host" }.map { (k, v) ->
                                k.name
                            }
                        }.firstOrNull()?.joinToString(separator = "") { "\n \u2022 $it" }
                        log += hosts

                    }
                }) {
                Text("View Binding")
            }

            Spacer(Modifier.size(16.dp))

            Button(
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.tertiary,
                    contentColor = MaterialTheme.colorScheme.onTertiary
                ),
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    scope.launch {
                        val certs =
                            dataStore.data.map { certs ->
                                certs[stringPreferencesKey(host)]
                            }.firstOrNull()?.let {
                                json.decodeFromString<AttestationResponse.Success>(it).certificateChain
                            }
                        if (certs != null) {
                            val intent = Intent(Intent.ACTION_SENDTO)
                            intent.setData(Uri.parse("mailto:")) // only email apps should handle this

                            intent.putExtra(Intent.EXTRA_SUBJECT, "Attested Binding")
                            intent.putExtra(Intent.EXTRA_TEXT, certs.joinToString(separator = "\n") {
                                "-----BEGIN CERTIFICATE-----\n" +
                                        Base64.getMimeEncoder().encodeToString(it.encoded) +
                                        "\n-----END CERTIFICATE-----"
                            })
                            startActivity(context, intent, null)
                        } else Toast.makeText(context, "No binding present for\n$host", Toast.LENGTH_LONG).show()
                    }
                }) {
                Text("Export Binding")
            }
        }
        Spacer(Modifier.size(16.dp))
        SelectionContainer { TextField(log, onValueChange = {}, modifier = Modifier.fillMaxSize(), readOnly = true) }

    }
}