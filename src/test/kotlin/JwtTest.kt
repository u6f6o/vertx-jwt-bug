import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.authentication.TokenCredentials
import io.vertx.ext.auth.jwt.JWTAuth
import io.vertx.junit5.VertxExtension
import io.vertx.junit5.VertxTestContext
import io.vertx.kotlin.ext.auth.jwt.jwtAuthOptionsOf
import io.vertx.kotlin.ext.auth.jwtOptionsOf
import io.vertx.kotlin.ext.auth.pubSecKeyOptionsOf
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import kotlin.random.Random

@ExtendWith(VertxExtension::class)
class JwtTest {

    private val charSamples = listOf(
            'ꌢ', '\uF289', '컸', 'ꁃ', '㳻', '洠', '⟜', '\uEDAC', '泰', '₦', '捇', '迷', '糼', '堛', '릙', 'Ü', '諄'
    )

    @Test
    fun testBreakIn(
            vertx: Vertx,
            testContext: VertxTestContext)
    {
        /**
         * First we create a secret with random length and shuffled !ascii chars.
         * We use this secret to generate the token.
         */
        val shuffledChars = charSamples.shuffled()
        val randomLengthChars = shuffledChars.take(Random.nextInt(1, charSamples.size + 1)).toCharArray()
        val secret = String(randomLengthChars)

        val jwtAuth = JWTAuth.create(vertx, jwtAuthOptionsOf().addPubSecKey(
                pubSecKeyOptionsOf(
                        algorithm = "HS256",
                        buffer = secret
                ))
        )

        val token = jwtAuth.generateToken(JsonObject(), jwtOptionsOf(algorithm = "HS256"))

        /**
         * Now let's try if we can break the verification
         */
        for (i in 1..1000) {
            if (testContext.completed()) { // fail fast if we succeeded
                break
            }
            /**
             * We choose a random character (!ascii) of your liking and concatenate as long
             * as we find the right secret length.
             */
            val fakeSecret = String(arrayOfNulls<Char>(i).map { '諄' }.toCharArray())

            val fakeAuth = JWTAuth.create(vertx, jwtAuthOptionsOf().addPubSecKey(
                    pubSecKeyOptionsOf(
                            algorithm = "HS256",
                            buffer = fakeSecret
                    ))
            )

            /**
             * Now we try to break the verification of the token we initially created.
             */
            val authFuture = fakeAuth.authenticate(TokenCredentials(token))
            authFuture.onSuccess {
                testContext.completeNow()
            }
        }
        if (!testContext.completed()) {
            testContext.failNow("Could not break in.")
        }
    }
}
