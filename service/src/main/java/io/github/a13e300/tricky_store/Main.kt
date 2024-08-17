package io.github.a13e300.tricky_store

import java.security.MessageDigest
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    Logger.i("Welcome to TrickyStore!")
    while (true) {
        if (!KeystoreInterceptor.tryRunKeystoreInterceptor()) {
            Thread.sleep(1000)
            continue
        }
        Config.initialize()
        while (true) {
            Thread.sleep(1000000)
        }
    }
}
