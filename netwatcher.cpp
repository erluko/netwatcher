# include <SystemConfiguration/SystemConfiguration.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

// MacOS/X Code taken from http://developer.apple.com/technotes/tn/tn1145.html
// VIA: https://public.msli.com/lcs/jaf/osx_ip_change_notify.cpp

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

struct callbackstate {
  char* path;
  pid_t last_pid;
  int run_again;
};

bool keep_running = true;
bool g_verbose = true;
#define LOG(...) do { if(g_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

#define FILENAME ".netwatch"

static void handler(struct callbackstate *state){
  if(state->last_pid){
    int status;
    if(waitpid(state->last_pid, &status, WNOHANG) > 0){
      if(WIFEXITED(status)){
        LOG("Child exited with status = %d\n",WEXITSTATUS(status));
      }
    }
    if(kill(state->last_pid, 0) != 0){
      state->run_again = 0;
    } else {
      LOG("Old process still running pid = %d\n",state->last_pid);
      state->run_again++;
      return;
    }
  }
  if(0 == access(state->path, X_OK)){
    LOG("Attempting to execute '%s'\n",state->path);
    pid_t pid = fork();
    if(pid == -1){
      LOG("Failed to fork\n");
      return;
    }
    if(pid == 0){
      execl(state->path, FILENAME , "IP_CHANGED", NULL);
      perror("Failed to execute ip change handler");
      exit(EXIT_FAILURE);
    } else {
      state->last_pid = pid;
    }
  } else {
    LOG("No executable file at '%s'\n",state->path);
  }
}
static void IPConfigChangedCallback(SCDynamicStoreRef /*store*/, CFArrayRef /*changedKeys*/, void *state)
{
  LOG("IP Configuration changed,\n");
  handler((struct callbackstate *)state);
}

void sighandler(int sig){
  switch(sig){
  case SIGTERM:
  case SIGINT:
    LOG("Received signal to exit\n");
    keep_running = false;
    CFRunLoopStop(CFRunLoopGetCurrent());
  }
}

void done(){
  LOG("Done listening for IP configuration changes\n");
}


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

int main(int argc, char **argv)
{
   close(STDIN_FILENO);
   int did_daemon;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
   did_daemon = 0 == daemon(1,1); //TODO: Switch to using launchd
#pragma clang diagnostic pop

   if(!did_daemon){
     perror("Unable to daemonize");
     return EXIT_FAILURE;
   }
   LOG("Daemonized. PID = %d\n",getpid());


   atexit(done);
   signal(SIGCHLD, SIG_IGN);
   signal(SIGTERM, sighandler);
   signal(SIGINT, sighandler);

   const char *homedir;

   if ((homedir = getenv("HOME")) == NULL) {
     homedir = getpwuid(getuid())->pw_dir;
   }

   LOG("Changing to %s\n", homedir);
   if(-1 == chdir(homedir)){
     perror("Unable to chdir to home directory");
     return EXIT_FAILURE;
   }

   size_t homelen = strnlen(homedir, PATH_MAX);
   size_t flen = strnlen(FILENAME, PATH_MAX);
   if(homelen >= PATH_MAX - flen - 1) {
     LOG("Path too long\n");
     return EXIT_FAILURE;
   }

   struct callbackstate state;
   state.run_again = 0;
   state.last_pid = 0;
   state.path = (char *) malloc(homelen + flen + 2);
   if(NULL == state.path){
     perror("Unable to allocate space to hold path to script");
     return EXIT_FAILURE;
   }
   memcpy(state.path, homedir, homelen);
   state.path[homelen]='/';
   memcpy(state.path + homelen + 1, FILENAME, flen);
   state.path[homelen+flen+1]='\0';
   LOG("Preparing to use '%s' as script path\n", state.path);

   SCDynamicStoreRef storeRef = NULL;
   CFRunLoopSourceRef sourceRef = NULL;
   if (CreateIPAddressListChangeCallbackSCF(IPConfigChangedCallback, &state, &storeRef, &sourceRef) == noErr)
   {
      CFRunLoopAddSource(CFRunLoopGetCurrent(), sourceRef, kCFRunLoopDefaultMode);
      LOG("Listening for IP configuration changes...\n");
      while(keep_running){
        CFRunLoopRun();
        if(keep_running){
          if(state.last_pid != 0){
            if(state.run_again > 12){
              kill(state.last_pid, SIGKILL);
              LOG("Abandoning stubborn child pid=%d\n", state.last_pid);
              state.run_again = 0;
              state.last_pid = 0;
            } else if(state.run_again > 4){
              kill(state.last_pid, SIGHUP);
            } else if(state.run_again > 8){
            kill(state.last_pid, SIGTERM);
            }
          }
          if(state.run_again > 0){
            handler(&state);
          }
        }
      }
      CFRunLoopRemoveSource(CFRunLoopGetCurrent(), sourceRef, kCFRunLoopDefaultMode);
      CFRelease(storeRef);
      CFRelease(sourceRef);
   }
}
