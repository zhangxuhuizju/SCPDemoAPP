package com.example.scptestapp;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.w3c.dom.Text;

import java.util.Timer;
import java.util.TimerTask;

import static android.net.wifi.SupplicantState.COMPLETED;

public class FirstTest extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }

    private static TextView tv;
    private static Button showResultButton;
    private static final int UPDATE = 0;
    private static final int FINISH = 1;
    private static final int UPLPADSUCCSEE = 2;
    private static final int UPLPADFAILED = 3;
    private static int recv = 0;
    private boolean finishTest = false;
    private static int testKind;
    private String ip;
    private int time;
    private static boolean bigPacket;

    private static Handler handler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            if (msg.what == UPDATE) {
                tv.setText("测试进行中，请勿离开界面\n已收到" + ++recv + "条push消息");
            } else if (msg.what == FINISH) {
                tv.setText("测试完成！\n共收到" + recv + "条push消息\n点击按钮可查看测试结果");
                showResultButton.setVisibility(View.VISIBLE);
            } else if (msg.what == UPLPADSUCCSEE) {
                tv.setText("log上传成功！");
            } else if (msg.what == UPLPADFAILED) {
                tv.setText("log上传失败！请手动上传！");
            }
        }
    };

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            if (!finishTest) {
                new AlertDialog.Builder(this)

                        .setMessage("Sure to exit?")
                        .setNegativeButton("No",
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int which) {
                                        dialog.dismiss();
                                    }
                                })
                        .setPositiveButton("Yes",
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int whichButton) {
                                        finish();
                                    }

                                }).show();
                return false;
            }
        }
        return true;
    }

    private BroadcastReceiver receiver = new NetworkChangeReceiver();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.test);

        IntentFilter filter = new IntentFilter();
        filter.addAction("android.net.conn.CONNECTIVITY_CHANGE");
        this.registerReceiver(receiver, filter);

        Intent intent = getIntent();
        ip = intent.getStringExtra("IP");
        testKind = intent.getIntExtra("TestKind", 0);
        bigPacket = intent.getBooleanExtra("BigPacket", false);
        time = intent.getIntExtra("time", 0);
        if (bigPacket)
            testKind += 1;

        recv = 0;
        tv = findViewById(R.id.testText);
        showResultButton = (Button)findViewById(R.id.resultShowButton);
        if (testKind != 6)
            tv.setText("测试进行中，请勿离开界面\n已收到" + recv + "条push消息");
        else
            tv.setText("长连接测试中，请勿离开界面！");

        TimerTask task = new TimerTask(){
            public void run(){
                //TODO  todo somthing here
                doTest();
            }
        };
        Timer timer = new Timer();
        //10秒后执行
        timer.schedule(task, 1 * 1000);
    }

    private void doTest() {
        startTest(ip, testKind, time);
    }

    public static void updateInfo() {
        Message msg = new Message();
        msg.what = UPDATE;
        handler.sendMessage(msg);
    }

    public static void finishTest() {
        Message msg = new Message();
        msg.what = FINISH;
        handler.sendMessage(msg);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(receiver);
    }

    public void showResult(View view) {
//        Intent intent = new Intent(this, ResultShow.class);
//        intent.putExtra("TestKind", testKind);
//        intent.putExtra("BigPacket", bigPacket);
//        startActivity(intent);
//        finish();
        new Thread() {
            @Override
            public void run() {
                String response = LogToHTTP.uploadLog("/data/data/com.example.scptestapp/result" + testKind + ".txt");
                System.out.println(response);
                if (response.equals("success")) {
                    Message msg = new Message();
                    msg.what =  UPLPADSUCCSEE;
                    handler.sendMessage(msg);
                } else {
                    Message msg = new Message();
                    msg.what = UPLPADFAILED;
                    handler.sendMessage(msg);
                }
            }
        }.start();
    }

    public native int startTest(String ip, int mode, int time);
}

