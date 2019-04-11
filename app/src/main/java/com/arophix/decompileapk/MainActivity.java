package com.arophix.decompileapk;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

public class MainActivity extends AppCompatActivity implements View.OnClickListener{
    
    static {
        System.loadLibrary("native-lib");
    }
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    
        Button showToastMessage = (Button) findViewById(R.id.showToastMessage);
        showToastMessage.setOnClickListener(this);
    }
    
    public boolean isPhoneRooted() {
        
        // get from build info
        String buildTags = android.os.Build.TAGS;
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true;
        }
        
        // check if /system/app/Superuser.apk is present
        try {
            File file = new File("/system/app/Superuser.apk");
            if (file.exists()) {
                return true;
            }
        } catch (Throwable e1) {
            // ignore
        }
        
        return false;
    }
    
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
    
    @Override
    public void onClick(View view) {
        if (isPhoneRooted()) {
            Toast.makeText(MainActivity.this, "Device rooted ...", Toast.LENGTH_LONG).show();
        } else {
            Toast.makeText(MainActivity.this, "Device not rooted ...", Toast.LENGTH_LONG).show();
        }
    
        Boolean bTamperingSucces = false;
    
        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        if (!bTamperingSucces) {
            tv.setText(stringFromJNI());
        } else {
            //tv.setText("Hello, Android reverse engineer!");
            tv.setText(stringFromJNI());
        }
    }
}
