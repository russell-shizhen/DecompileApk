package com.arophix.decompileapk;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    
    static {
        System.loadLibrary("native-lib");
    }
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        Boolean bTamperingSucces = false;
    
        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        if (!bTamperingSucces) {
            tv.setText(stringFromJNI());
        } else {
            tv.setText("Hello, Android reverse engineer!");
        }
    }
    
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
