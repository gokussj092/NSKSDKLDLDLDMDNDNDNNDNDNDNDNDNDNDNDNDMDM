#pragma once
#include <jni.h>

namespace spdecode {
jstring currentHardwarePublicKey(JNIEnv* env);
jobject privateSigningKeyForBearer(JNIEnv* env, jstring bearer);
jobjectArray createHardwareAttestation(JNIEnv* env,jstring challenge,jstring level);
} // namespace spdecode
