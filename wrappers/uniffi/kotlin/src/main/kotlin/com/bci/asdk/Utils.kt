package com.bci.asdk

import java.io.File

fun setJniLibPath() {
    System.setProperty("jna.library.path", File("../../../target/debug").canonicalPath)
}