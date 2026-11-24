-dontshrink
-dontoptimize
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,Record,Exceptions,StackMapTable
-keep @net.minecraftforge.fml.common.Mod class * {
    public <init>();
}
-keepclassmembers class * {
    @net.minecraftforge.eventbus.api.SubscribeEvent <methods>;
}
-keep interface * extends com.sun.jna.Library { *; }
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
