package at.asitplus

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.configureRouting() {
    routing {
        get("/") {
            call.respondText("Hello World!")
        }
        authenticate("jwt") {
            get("/protected") {
                val authenticatedSubject = call.principal<UserIdPrincipal>()
                val message =
                    "Welcome, ${authenticatedSubject?.name?.substring(3)}!" + "\nThis message is for your eyes only."
                call.respondText(message, ContentType.Text.Plain.withCharset(Charsets.UTF_8))
            }
        }
    }
}
