@ stdcall BCryptOpenAlgorithmProvider(ptr wstr wstr long)
@ stdcall BCryptCloseAlgorithmProvider(ptr long)
@ stdcall BCryptCreateHash(ptr ptr ptr long ptr long long)
@ stdcall BCryptHashData(ptr ptr long long)
@ stdcall BCryptFinishHash(ptr ptr long long)
@ stdcall BCryptDestroyHash(ptr)
@ stdcall BCryptGenRandom(ptr ptr long long) ksecdd.BCryptGenRandom
