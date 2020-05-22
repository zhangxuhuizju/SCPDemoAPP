package com.example.scptestapp;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.PermissionChecker;

import android.Manifest;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.drawable.AnimationDrawable;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.hb.dialog.dialog.LoadingDialog;
import com.hb.dialog.myDialog.MyAlertInputDialog;
import com.hb.dialog.myDialog.MyImageMsgDialog;

public class MainActivity extends AppCompatActivity {
    static {
        System.loadLibrary("native-lib");
    }

    private void getPermission(){
        if(PermissionChecker.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)==PermissionChecker.PERMISSION_DENIED){
            ActivityCompat.requestPermissions(this, new String[]{
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                    "android.permission.READ_EXTERNAL_STORAGE",
            },100);
        }
    }

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    final static String IP = "49.4.51.131";

//    LoadingDialog loadingDialog;
//    private void doLoading(){
//        loadingDialog = new LoadingDialog(this);
//        loadingDialog.setMessage("connecting");
//        loadingDialog.show();
//    }
//
//    public void closeLoading() {
//        loadingDialog.dismiss();
//        Toast toast=Toast.makeText(getApplicationContext(), "连接成功！", Toast.LENGTH_SHORT);
//        toast.show();
//    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        getPermission();

//        final MyAlertInputDialog myAlertInputDialog = new MyAlertInputDialog(this).builder()
//                .setTitle("请输入测试服务器IP")
//                .setEditText("");
//        myAlertInputDialog.setPositiveButton("确认", new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                IP = myAlertInputDialog.getResult();
//                myAlertInputDialog.dismiss();
////                doLoading();
//            }
//        });
//        myAlertInputDialog.show();
    }

    private void chooseMode() {
        new AlertDialog.Builder(this)

                .setMessage("开启大小包混合测试？")
                .setNegativeButton("否",
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                                intent.putExtra("BigPacket", bigPacket);
                                startActivity(intent);
                            }
                        })
                .setPositiveButton("是",
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int whichButton) {
                                bigPacket = true;
                                dialog.dismiss();
                                intent.putExtra("BigPacket", bigPacket);
                                startActivity(intent);
                            }

                        }).show();
    }

    private boolean bigPacket = false;
    Intent intent;

    public void startTest1 (View view) {
        intent = new Intent(this, FirstTest.class);
        intent.putExtra("IP", IP);
        intent.putExtra("TestKind", 0);
        chooseMode();
//        System.out.println(System.currentTimeMillis());
//        intent.putExtra("BigPacket", bigPacket);
//        startActivity(intent);
    }

    public void startTest2 (View view) {
        intent = new Intent(this, FirstTest.class);
        intent.putExtra("IP", IP);
        intent.putExtra("TestKind", 2);
        chooseMode();
//        intent.putExtra("BigPacket", bigPacket);
//        startActivity(intent);
    }

    public void startTest3 (View view) {
        intent = new Intent(this, FirstTest.class);
        intent.putExtra("IP", IP);
        intent.putExtra("TestKind", 4);
        chooseMode();
//        intent.putExtra("BigPacket", bigPacket);
//        startActivity(intent);
    }

    public void startTest4 (View view) {
        intent = new Intent(this, FirstTest.class);
        intent.putExtra("IP", IP);
        intent.putExtra("TestKind", 6);
        final MyAlertInputDialog myAlertInputDialog = new MyAlertInputDialog(this).builder()
                .setTitle("请输入心跳包周期(单位s)")
                .setEditText("");
        myAlertInputDialog.setPositiveButton("确认", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int time = Integer.parseInt(myAlertInputDialog.getResult());
                myAlertInputDialog.dismiss();
                intent.putExtra("time", time);
                startActivity(intent);
            }
        });
        myAlertInputDialog.show();
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
}
