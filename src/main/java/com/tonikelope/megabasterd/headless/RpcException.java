package com.tonikelope.megabasterd.headless;
public final class RpcException extends Exception {
    public final int code;
    public RpcException(int code,String message) { super(message); this.code=code; }
}
