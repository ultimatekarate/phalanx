//
//  Generated file. Do not edit.
//

// clang-format off

#import "GeneratedPluginRegistrant.h"

#if __has_include(<app_links/AppLinksIosPlugin.h>)
#import <app_links/AppLinksIosPlugin.h>
#else
@import app_links;
#endif

#if __has_include(<battery_plus/FPPBatteryPlusPlugin.h>)
#import <battery_plus/FPPBatteryPlusPlugin.h>
#else
@import battery_plus;
#endif

#if __has_include(<camera_avfoundation/CameraPlugin.h>)
#import <camera_avfoundation/CameraPlugin.h>
#else
@import camera_avfoundation;
#endif

#if __has_include(<file_picker/FilePickerPlugin.h>)
#import <file_picker/FilePickerPlugin.h>
#else
@import file_picker;
#endif

#if __has_include(<flutter_pcm_sound/FlutterPcmSoundPlugin.h>)
#import <flutter_pcm_sound/FlutterPcmSoundPlugin.h>
#else
@import flutter_pcm_sound;
#endif

#if __has_include(<flutter_secure_storage/FlutterSecureStoragePlugin.h>)
#import <flutter_secure_storage/FlutterSecureStoragePlugin.h>
#else
@import flutter_secure_storage;
#endif

#if __has_include(<mobile_scanner/MobileScannerPlugin.h>)
#import <mobile_scanner/MobileScannerPlugin.h>
#else
@import mobile_scanner;
#endif

#if __has_include(<record_darwin/RecordPlugin.h>)
#import <record_darwin/RecordPlugin.h>
#else
@import record_darwin;
#endif

#if __has_include(<share_plus/FPPSharePlusPlugin.h>)
#import <share_plus/FPPSharePlusPlugin.h>
#else
@import share_plus;
#endif

@implementation GeneratedPluginRegistrant

+ (void)registerWithRegistry:(NSObject<FlutterPluginRegistry>*)registry {
  [AppLinksIosPlugin registerWithRegistrar:[registry registrarForPlugin:@"AppLinksIosPlugin"]];
  [FPPBatteryPlusPlugin registerWithRegistrar:[registry registrarForPlugin:@"FPPBatteryPlusPlugin"]];
  [CameraPlugin registerWithRegistrar:[registry registrarForPlugin:@"CameraPlugin"]];
  [FilePickerPlugin registerWithRegistrar:[registry registrarForPlugin:@"FilePickerPlugin"]];
  [FlutterPcmSoundPlugin registerWithRegistrar:[registry registrarForPlugin:@"FlutterPcmSoundPlugin"]];
  [FlutterSecureStoragePlugin registerWithRegistrar:[registry registrarForPlugin:@"FlutterSecureStoragePlugin"]];
  [MobileScannerPlugin registerWithRegistrar:[registry registrarForPlugin:@"MobileScannerPlugin"]];
  [RecordPlugin registerWithRegistrar:[registry registrarForPlugin:@"RecordPlugin"]];
  [FPPSharePlusPlugin registerWithRegistrar:[registry registrarForPlugin:@"FPPSharePlusPlugin"]];
}

@end
