package com.cnting.nativehookstudy

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import com.cnting.nativehookstudy.databinding.ActivityMainBinding
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Example of a call to a native method
        binding.sampleText.text = stringFromJNI()
        binding.sampleText.setOnClickListener {
            thread {
                Log.d("===>","有一个线程运行了")
                Thread.sleep(10000)
            }
        }
    }

    /**
     * A native method that is implemented by the 'nativehookstudy' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    companion object {
        // Used to load the 'nativehookstudy' library on application startup.
        init {
            System.loadLibrary("nativehookstudy")
        }
    }
}