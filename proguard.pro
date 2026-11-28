-dontshrink
-dontoptimize
-flattenpackagehierarchy org.acivllas.internal
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,Record,Exceptions,StackMapTable
-keep @net.minecraftforge.fml.common.Mod class * {
    public <init>();
}
-keepclassmembers,allowobfuscation class * {
    @net.minecraftforge.eventbus.api.SubscribeEvent <methods>;
}
-keep interface * extends com.sun.jna.Library { *; }
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
