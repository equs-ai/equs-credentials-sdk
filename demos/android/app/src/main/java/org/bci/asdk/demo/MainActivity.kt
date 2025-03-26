package org.bci.asdk.demo

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModelProvider
import org.bci.asdk.demo.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {
    private lateinit var viewModel: DemoViewModel
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this)[DemoViewModel::class.java]

        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Screen(
                            viewModel,
                            innerPadding
                    )
                }
            }
        }
    }
}

@Composable
fun Screen(viewModel: DemoViewModel, paddingValues: PaddingValues) {
    val authRequests by viewModel.authRequest.collectAsState(initial = null)
    val credential by viewModel.credential.collectAsState(initial = null)
    val presentationRequest by viewModel.presentationRequest.collectAsState(initial = null)

    var userInput by remember { mutableStateOf("") }
    var currentUrl by remember { mutableStateOf<String?>(null) }
    var sdJwt by remember { mutableStateOf<String?>(null) }
    var presentationDefinition by remember { mutableStateOf<String?>(null) }

    val context = LocalContext.current

    var authComplete by remember { mutableStateOf(false) }
    var issuanceComplete by remember { mutableStateOf(false) }

    LaunchedEffect(authRequests) {
        authRequests?.let {
            currentUrl = it
        }
    }

    LaunchedEffect(credential) {
        credential?.let {
            sdJwt = it.payload
        }
    }

    LaunchedEffect(presentationRequest) {
        presentationRequest?.let {
            presentationDefinition = it.presentationDefinition
        }
    }

    Column(modifier = Modifier.padding(paddingValues)) {
        // OID4VCI Authorization Code flow
        if (!authComplete) {
            if (currentUrl == null) {
                Column(
                    modifier = Modifier.fillMaxWidth().fillMaxHeight(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Button(
                        onClick = { viewModel.startAuthentication() }
                    ) {
                        Text("Start Authentication")
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            currentUrl?.let { url ->
                Column(
                    modifier = Modifier.fillMaxWidth().fillMaxHeight(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "Please enter authorization code from:",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = AnnotatedString(url),
                        style = MaterialTheme.typography.bodyMedium.copy(
                            color = MaterialTheme.colorScheme.primary
                        ),
                        modifier = Modifier
                            .padding(vertical = 8.dp)
                            .fillMaxWidth()
                            .background(
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                shape = RoundedCornerShape(4.dp)
                            )
                            .padding(8.dp)
                            .clickable {
                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                context.startActivity(intent)
                            }
                    )

                    TextField(
                        value = userInput,
                        onValueChange = { userInput = it },
                        label = { Text("Authorization Code") }
                    )

                    Button(
                        onClick = {
                            viewModel.submitCode(url, userInput)
                            userInput = ""
                            currentUrl = null
                            authComplete = true
                        }
                    ) {
                        Text("Submit Code")
                    }
                }
            }
        }

        if (authComplete && !issuanceComplete) {
            Column(
                modifier = Modifier.fillMaxWidth().fillMaxHeight(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Button(
                    onClick = {
                        viewModel.startCredentialRequest()
                        issuanceComplete = true
                    }
                ) {
                    Text("Start issuance")
                }
            }
        }

        if (issuanceComplete) {
            Column(
                modifier = Modifier.fillMaxWidth().fillMaxHeight(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                sdJwt?.let { cred ->
                    CopyableText(text = cred)
                }
                Text(
                    text = "Please enter authorization url from:",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = AnnotatedString(VP_REQUEST_URI),
                    style = MaterialTheme.typography.bodyMedium.copy(
                        color = MaterialTheme.colorScheme.primary
                    ),
                    modifier = Modifier
                        .padding(vertical = 8.dp)
                        .fillMaxWidth()
                        .background(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = RoundedCornerShape(4.dp)
                        )
                        .padding(8.dp)
                        .clickable {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(VP_REQUEST_URI))
                            context.startActivity(intent)
                        }
                )

                TextField(
                    value = userInput,
                    onValueChange = { userInput = it },
                    label = { Text("Authorization Request URI") }
                )

                Button(
                    onClick = {
                        viewModel.starPresentation(userInput)
                        userInput = ""
                    }
                ) {
                    Text("Start presentation")
                }
            }
        }

        presentationDefinition?.let { prs ->
            CopyableText(text = prs)
        }
    }
}

@Composable
fun CopyableText(text: String) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(4.dp)
            )
            .clickable {
                clipboardManager.setText(AnnotatedString(text))
                Toast
                    .makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT)
                    .show()
            }
            .padding(12.dp)
    ) {
        Text(
            text = text,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            style = MaterialTheme.typography.bodyMedium
        )

        Spacer(modifier = Modifier.width(8.dp))
    }
}