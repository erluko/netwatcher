# include <SystemConfiguration/SystemConfiguration.h>

// MacOS/X Code taken from http://developer.apple.com/technotes/tn/tn1145.html
static OSStatus MoreSCErrorBoolean(Boolean success)
{
   OSStatus err = noErr;
   if (!success) 
   {
      int scErr = SCError();
      if (scErr == kSCStatusOK) scErr = kSCStatusFailed;
      err = scErr;
   }
   return err;
}

static OSStatus MoreSCError(const void *value) {return MoreSCErrorBoolean(value != NULL);}
static OSStatus CFQError(CFTypeRef cf) {return (cf == NULL) ? -1 : noErr;}
static void CFQRelease(CFTypeRef cf) {if (cf != NULL) CFRelease(cf);}

// Create a SCF dynamic store reference and a corresponding CFRunLoop source.  If you add the
// run loop source to your run loop then the supplied callback function will be called when local IP
// address list changes.
static OSStatus CreateIPAddressListChangeCallbackSCF(SCDynamicStoreCallBack callback, void *contextPtr, SCDynamicStoreRef *storeRef, CFRunLoopSourceRef *sourceRef)
{
   OSStatus                err;
   SCDynamicStoreContext   context = {0, NULL, NULL, NULL, NULL};
   SCDynamicStoreRef       ref = NULL;
   CFStringRef             patterns[2] = {NULL, NULL};
   CFArrayRef              patternList = NULL;
   CFRunLoopSourceRef      rls = NULL;

   assert(callback   != NULL);
   assert( storeRef  != NULL);
   assert(*storeRef  == NULL);
   assert( sourceRef != NULL);
   assert(*sourceRef == NULL);

   // Create a connection to the dynamic store, then create
   // a search pattern that finds all entities.
   context.info = contextPtr;
   ref = SCDynamicStoreCreate(NULL, CFSTR("AddIPAddressListChangeCallbackSCF"), callback, &context);
   err = MoreSCError(ref);
   if (err == noErr) 
   {
      // This pattern is "State:/Network/Service/[^/]+/IPv4".
      patterns[0] = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
      err = MoreSCError(patterns[0]);
      if (err == noErr)
      {
         // This pattern is "State:/Network/Service/[^/]+/IPv6".
         patterns[1] = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv6);
         err = MoreSCError(patterns[1]);
      }
   }

   // Create a pattern list containing just one pattern,
   // then tell SCF that we want to watch changes in keys
   // that match that pattern list, then create our run loop
   // source.
   if (err == noErr) 
   {
       patternList = CFArrayCreate(NULL, (const void **) patterns, 2, &kCFTypeArrayCallBacks);
       err = CFQError(patternList);
   }
   if (err == noErr) err = MoreSCErrorBoolean(SCDynamicStoreSetNotificationKeys(ref, NULL, patternList));
   if (err == noErr) 
   {
       rls = SCDynamicStoreCreateRunLoopSource(NULL, ref, 0);
       err = MoreSCError(rls);
   }

   // Clean up.
   CFQRelease(patterns[0]);
   CFQRelease(patterns[1]);
   CFQRelease(patternList);
   if (err != noErr) 
   {
      CFQRelease(ref);
      ref = NULL;
   }
   *storeRef = ref;
   *sourceRef = rls;

   assert( (err == noErr) == (*storeRef  != NULL) );
   assert( (err == noErr) == (*sourceRef != NULL) );

   return err;
}

static void IPConfigChangedCallback(SCDynamicStoreRef /*store*/, CFArrayRef /*changedKeys*/, void * info)
{
   printf("IP Configuration changed, do something!\n");
}

volatile bool _threadKeepGoing = true;  // in real life another thread might tell us to quit by setting this false and then calling CFRunLoopStop() on our CFRunLoop()

int main(int, char **)
{
   printf("Listening for IP configuration changes...\n");

   void * contextPtr = NULL;  // only NULL for this trivial example; in real life you could point this to some data you want the IPConfigChangedCallback() to have access to
   SCDynamicStoreRef storeRef = NULL;
   CFRunLoopSourceRef sourceRef = NULL;
   if (CreateIPAddressListChangeCallbackSCF(IPConfigChangedCallback, contextPtr, &storeRef, &sourceRef) == noErr)
   {
      CFRunLoopAddSource(CFRunLoopGetCurrent(), sourceRef, kCFRunLoopDefaultMode);
      while(_threadKeepGoing) CFRunLoopRun();
      CFRunLoopRemoveSource(CFRunLoopGetCurrent(), sourceRef, kCFRunLoopDefaultMode);
      CFRelease(storeRef);
      CFRelease(sourceRef);
   }
}
