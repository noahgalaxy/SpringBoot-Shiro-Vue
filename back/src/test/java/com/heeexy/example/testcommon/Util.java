package com.heeexy.example.testcommon;

public class Util {
    public static void changeNum(int num){
        num++;
        System.out.println("changeNum里面修改后的num的值为："+num);
    }

    public static void main(String[] args) {
        int num = 1;
        Util.changeNum(num);
        System.out.println("main里面的最后num的值为"+num);
    }

}
