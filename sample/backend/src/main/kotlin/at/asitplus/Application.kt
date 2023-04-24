package at.asitplus

import at.asitplus.plugins.attestation.configureAttestation
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import org.slf4j.event.Level

fun main(args: Array<String>): Unit =
    io.ktor.server.cio.EngineMain.main(args)

@Suppress("unused") // application.conf references the main function. This annotation prevents the IDE from marking it as unused.
fun Application.module() {
    configureAttestation()
    configureSerialization()
    configureSecurity()
    configureRouting()
    install(StatusPages) {
        status(HttpStatusCode.Unauthorized) { call, status ->
            call.respondText(text = status.description, status = status)
        }
    }
    install(CallLogging) {
        level = Level.TRACE
        filter { call -> call.request.path().startsWith("/") }
    }
}
