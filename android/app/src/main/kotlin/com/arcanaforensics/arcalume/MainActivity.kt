package com.arcanaforensics.arcalume

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import com.arcanaforensics.arcalume.ui.AppViewModel
import com.arcanaforensics.arcalume.ui.ArcalumeRoot
import com.arcanaforensics.arcalume.ui.ArcalumeTheme

class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (savedInstanceState == null) handle(intent)
        setContent { ArcalumeTheme { ArcalumeRoot(vm) } }
    }

    override fun onResume() {
        super.onResume()
        (application as ArcalumeApp).pro.tick()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    /**
     * "Share to Arcalume". Each file is read once, through the grant that came with it. A photo
     * shared to "Recover with Arcalume" opens in Recover; anything shared to "Add to Arcalume
     * case" (chat exports, documents, several files at once) is added to the case as exhibits.
     */
    private fun handle(intent: Intent?) {
        val uris: List<Uri> = when (intent?.action) {
            Intent.ACTION_SEND -> listOfNotNull(
                if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                else @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_STREAM),
            )
            Intent.ACTION_SEND_MULTIPLE -> (
                if (Build.VERSION.SDK_INT >= 33) intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                else @Suppress("DEPRECATION") intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
            ).orEmpty()
            else -> return
        }
        if (uris.isEmpty()) return
        val type = intent.type.orEmpty()
        val viaCase = intent.component?.className?.endsWith(".AddToCase") == true
        if (!viaCase && intent.action == Intent.ACTION_SEND && type.startsWith("image/")) vm.importUris(uris) else vm.addToCase(uris)
    }
}
