# Introduction

FreeRDP의 rdpdr channel에서 발생하는 read of uninitialized memory 취약점 (CVE-2022-39282)과 tsmf channel에서 발생하는 Heap-based Buffer Overflow 취약점 ([Patch](https://github.com/FreeRDP/FreeRDP/commit/26ac2f0b271726b7e344a2b9d6a6e319b52ee8c0))를 소개하고, 두 개의 취약점을 이용해 RCE를 달성하기까지의 과정을 소개한다.

# What is FreeRDP?

[FreeRDP](https://github.com/FreeRDP/FreeRDP)는 오픈소스로 관리되는 RDP 구현체로

# The Bugs

## Read of Uninitialized Memory

`parallel_process_irp_read` 는 `parallel->file`로부터 원하는 길이의 데이터를 읽어오는 함수이다. 그런데 만약 `parallel->file`의 크기가 Length보다 작다면, buffer에 uninitialize된 data가 남아 있게 되고, 이를 그대로 서버로 전송하기 때문에 취약점이 발생하게 된다.

```c
static UINT parallel_process_irp_read(PARALLEL_DEVICE* parallel, IRP* irp)
{
	UINT32 Length;
	UINT64 Offset;
	ssize_t status;
	BYTE* buffer = NULL;
	if (!Stream_CheckAndLogRequiredLength(TAG, irp->input, 12))
		return ERROR_INVALID_DATA;
	Stream_Read_UINT32(irp->input, Length);
	Stream_Read_UINT64(irp->input, Offset);
	buffer = (BYTE*)malloc(Length);

	if (!buffer)
	{
		WLog_ERR(TAG, "malloc failed!");
		return CHANNEL_RC_NO_MEMORY;
	}

	status = read(parallel->file, buffer, Length);

	if (status < 0)
	{
		irp->IoStatus = STATUS_UNSUCCESSFUL;
		free(buffer);
		buffer = NULL;
		Length = 0;
	}
	else
	{
	}

	Stream_Write_UINT32(irp->output, Length);

	if (Length > 0)
	{
		if (!Stream_EnsureRemainingCapacity(irp->output, Length))
		{
			WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed!");
			free(buffer);
			return CHANNEL_RC_NO_MEMORY;
		}

		Stream_Write(irp->output, buffer, Length);
	}

	free(buffer);
	return irp->Complete(irp);
}
```

## Heap-based Buffer Overflow

# Exploitation

## Step 1. Library Address Leak

Library Address Leak을 위해서 Library 영역의 주소가 적힌 Free된 Chunk가 필요한데, 이는 `irp_new`에서 할당 받은 `irp` 구조체를 이용하여 해결했다.

`RDPDR` 채널에 취약점을 트리거하는 메세지를 보내면 `rdpdr_process_receive` 함수에서 메세지를 parsing하여 처리한다. 이때 취약점이 발생하는 IOREQUEST를 보내면 `rdpdr_process_irp` 함수가 호출되게 된다.

```
static UINT rdpdr_process_receive(rdpdrPlugin* rdpdr, wStream* s)
{
	UINT16 component;
	UINT16 packetId;
	UINT32 deviceId;
	UINT32 status;
	UINT error = ERROR_INVALID_DATA;

	if (!rdpdr || !s)
		return CHANNEL_RC_NULL_DATA;

	rdpdr_dump_received_packet(s, "rdpdr-channel");
	if (Stream_GetRemainingLength(s) >= 4)
	{
		Stream_Read_UINT16(s, component); /* Component (2 bytes) */
		Stream_Read_UINT16(s, packetId);  /* PacketId (2 bytes) */

		if (component == RDPDR_CTYP_CORE)
		{
			switch (packetId)
			{
				...

				case PAKID_CORE_DEVICE_IOREQUEST:
					if ((error = rdpdr_process_irp(rdpdr, s)))
					{
						WLog_ERR(TAG, "rdpdr_process_irp failed with error %" PRIu32 "", error);
						return error;
					}
					else
						s = NULL;

					break;

				...
			}
		}
		else
		{
			...
		}
	}

	return error;
}
```

`rdpdr_process_irp` 함수에서는 `irp` 구조체를 할당 받는 `irp_new` 함수를 호출하고, `IFCALLRET` 매크로를 사용해 `parallel_process_irp` 를 호출한다.

```c
static UINT rdpdr_process_irp(rdpdrPlugin* rdpdr, wStream* s)
{
	IRP* irp;
	UINT error = CHANNEL_RC_OK;

	WINPR_ASSERT(rdpdr);
	WINPR_ASSERT(s);

	irp = irp_new(rdpdr->devman, rdpdr->pool, s, &error);

	if (!irp)
	{
		...
		return error;
	}

	IFCALLRET(irp->device->IRPRequest, error, irp->device, irp);

	if (error)
		WLog_ERR(TAG, "device->IRPRequest failed with error %" PRIu32 "", error);

	return error;
}
```

`irp_new` 함수에서는 `irp`에 library 영역의 주소인 `irp_complete`, `irp_free` 와 힙 영역의 주소인  `s`, `device`, `devman` 를 써준다.

```c
IRP* irp_new(DEVMAN* devman, wStreamPool* pool, wStream* s, UINT* error)
{
	IRP* irp;
	DEVICE* device;
	UINT32 DeviceId;

	WINPR_ASSERT(devman);
	WINPR_ASSERT(pool);
	WINPR_ASSERT(s);

	...

	irp = (IRP*)winpr_aligned_malloc(sizeof(IRP), MEMORY_ALLOCATION_ALIGNMENT);

	if (!irp)
	{
		WLog_ERR(TAG, "_aligned_malloc failed!");
		if (error)
			*error = CHANNEL_RC_NO_MEMORY;
		return NULL;
	}

	ZeroMemory(irp, sizeof(IRP));

	Stream_Read_UINT32(s, irp->FileId);        /* FileId (4 bytes) */
	Stream_Read_UINT32(s, irp->CompletionId);  /* CompletionId (4 bytes) */
	Stream_Read_UINT32(s, irp->MajorFunction); /* MajorFunction (4 bytes) */
	Stream_Read_UINT32(s, irp->MinorFunction); /* MinorFunction (4 bytes) */

	Stream_AddRef(s);
	irp->input = s;
	irp->device = device;
	irp->devman = devman;

	irp->output = StreamPool_Take(pool, 256);
	
  ...

	irp->Complete = irp_complete;
	irp->Discard = irp_free;

	irp->thread = NULL;
	irp->cancelled = FALSE;

	if (error)
		*error = CHANNEL_RC_OK;

	return irp;
}
```

이후 `IFCALLRET` 매크로로 호출 되는 `parallel_process_irp` 에서는 `MajorFunction`에 따라 세부적으로 요청을 처리한 뒤 `irp` 구조체를 free하게 된다.

```c
static UINT parallel_process_irp(PARALLEL_DEVICE* parallel, IRP* irp)
{
	UINT error;

	switch (irp->MajorFunction)
	{
		case IRP_MJ_CREATE:
			if ((error = parallel_process_irp_create(parallel, irp)))
			{
				WLog_ERR(TAG, "parallel_process_irp_create failed with error %" PRIu32 "!", error);
				return error;
			}

			break;

		case IRP_MJ_CLOSE:
			if ((error = parallel_process_irp_close(parallel, irp)))
			{
				WLog_ERR(TAG, "parallel_process_irp_close failed with error %" PRIu32 "!", error);
				return error;
			}

			break;

		case IRP_MJ_READ:
			if ((error = parallel_process_irp_read(parallel, irp)))
			{
				WLog_ERR(TAG, "parallel_process_irp_read failed with error %" PRIu32 "!", error);
				return error;
			}

			break;

		case IRP_MJ_WRITE:
			if ((error = parallel_process_irp_write(parallel, irp)))
			{
				WLog_ERR(TAG, "parallel_process_irp_write failed with error %" PRIu32 "!", error);
				return error;
			}

			break;

		case IRP_MJ_DEVICE_CONTROL:
			if ((error = parallel_process_irp_device_control(parallel, irp)))
			{
				WLog_ERR(TAG, "parallel_process_irp_device_control failed with error %" PRIu32 "!",
				         error);
				return error;
			}

			break;

		default:
			irp->IoStatus = STATUS_NOT_SUPPORTED;
			return irp->Complete(irp);
	}

	return CHANNEL_RC_OK;
}
```

예시로 `parallel_process_irp_create` 함수를 살펴보면 create요청을 수행한 뒤, `irp->Complete(irp)` 를 호출해 `irp` 구조체를 free한다.

```c
static UINT parallel_process_irp_create(PARALLEL_DEVICE* parallel, IRP* irp)
{
	char* path = NULL;
	int status;
	WCHAR* ptr;
	UINT32 PathLength;
	
  ...

	Stream_Write_UINT32(irp->output, parallel->id);
	Stream_Write_UINT8(irp->output, 0);
	free(path);
	return irp->Complete(irp);
}
static UINT irp_complete(IRP* irp)
{
	size_t pos;
	rdpdrPlugin* rdpdr;
	UINT error;

	rdpdr = (rdpdrPlugin*)irp->devman->plugin;

	pos = Stream_GetPosition(irp->output);
	Stream_SetPosition(irp->output, RDPDR_DEVICE_IO_RESPONSE_LENGTH - 4);
	Stream_Write_UINT32(irp->output, irp->IoStatus); /* IoStatus (4 bytes) */
	Stream_SetPosition(irp->output, pos);

	error = rdpdr_send(rdpdr, irp->output);
	irp->output = NULL;

	irp_free(irp);
	return error;
}
```

따라서 취약점이 발생하는 `parallel_process_irp_read` 를 호출하기 전에 임의의 parallel iorequest를 보내면, `irp` 구조체가 free list에 들어가 있는 상태가 되고, `irp` 구조체와 같은 크기(0x80)의 chunk를 할당 받도록 하면, library, heap address를 leak 할 수 있게 된다.

## Step 2. Spray Vtables

다음 취약점을 이용해 원하는 크기의 chunk를 할당 받아 원하는 길이만큼 overwrite 할 수 있다

[[cve 제보 보고서 완료\] [보고서 작성 완료] FreeRDP Heap-Buffer-Overflow (TSMF)](https://www.notion.so/cve-FreeRDP-Heap-Buffer-Overflow-TSMF-4d8a1a0757594b049c205e638d834cd7)

heap overflow로 실행 흐름을 바꾸기 위해서 vtable을 overwrite하는 방법을 생각할 수 있다. 이때 exploit의 확률을 높이기 위해 Heap Spray를 사용하였다.

Spray한 vtable은 Echo Channel의 vtable을 사용했다.

Echo Channel을 열도록 요청하면, `drdynvc_process_create_request` 함수가 실행된다.

해당 함수에서는 내부적으로 `dvcman_create_channel`과 `dvcman_open_channel` 를 호출한다. (Echo Channel은 Open callback함수가 없어 `dvcman_open_channel` 은 아무 것도 하지 않는다.)

```c
static UINT drdynvc_process_create_request(drdynvcPlugin* drdynvc, int Sp, int cbChId, wStream* s)
{
	size_t pos;
	UINT status;
	UINT32 ChannelId;
	wStream* data_out;
	UINT channel_status;
	char* name;
	size_t length;
	DVCMAN* dvcman;
	DVCMAN_CHANNEL* channel;
	UINT32 retStatus;

	...

	channel =
	    dvcman_create_channel(drdynvc, drdynvc->channel_mgr, ChannelId, name, &channel_status);
	
  ...

	if (channel_status == CHANNEL_RC_OK)
	{
		if ((status = dvcman_open_channel(drdynvc, channel)))
		{
			WLog_Print(drdynvc->log, WLOG_ERROR,
			           "dvcman_open_channel failed with error %" PRIu32 "!", status);
			return status;
		}
	}

	return status;
}
```

`dvcman_create_channel` 함수에서는 HashTable을 이용해 중복된 channel Id가 있는지 확인하고, 없다면 `dvcman_channel_new`을 이용해 `DVCMAN_CHANNEL` 구조체를 할당 받고, semaphore를 이용해 lock을 거는 과정에서 `winpr_sem_t` 공용체를 할당 받는다.

그리고 Hash Table에 Channel을 insert하면서 `wKeyValuePair` 구조체를 할당받는다.

이후 `listener->listener_callback->OnNewChannelConnection` 이 호출되면서 `GENERIC_CHANNEL_CALLBACK` 구조체를 할당 받는다.

```c
static DVCMAN_CHANNEL* dvcman_create_channel(drdynvcPlugin* drdynvc,
                                             IWTSVirtualChannelManager* pChannelMgr,
                                             UINT32 ChannelId, const char* ChannelName, UINT* res)
{
	BOOL bAccept;
	DVCMAN_CHANNEL* channel = NULL;
	DrdynvcClientContext* context;
	DVCMAN* dvcman = (DVCMAN*)pChannelMgr;
	DVCMAN_LISTENER* listener;
	IWTSVirtualChannelCallback* pCallback = NULL;

	WINPR_ASSERT(res);

	HashTable_Lock(dvcman->listeners);
	listener = (DVCMAN_LISTENER*)HashTable_GetItemValue(dvcman->listeners, ChannelName);
	if (!listener)
	{
		*res = ERROR_NOT_FOUND;
		goto out;
	}

	channel = dvcman_get_channel_by_id(pChannelMgr, ChannelId, FALSE);
	if (channel)
	{
		switch (channel->state)
		{
			case DVC_CHANNEL_RUNNING:
				WLog_Print(drdynvc->log, WLOG_ERROR,
				           "Protocol error: Duplicated ChannelId %" PRIu32 " (%s)!", ChannelId,
				           ChannelName);
				*res = CHANNEL_RC_ALREADY_OPEN;
				goto out;

			case DVC_CHANNEL_CLOSED:
			case DVC_CHANNEL_INIT:
			default:
				WLog_Print(drdynvc->log, WLOG_ERROR, "not expecting a createChannel from state %d",
				           channel->state);
				*res = CHANNEL_RC_INITIALIZATION_ERROR;
				goto out;
		}
	}
	else
	{
		if (!(channel = dvcman_channel_new(drdynvc, pChannelMgr, ChannelId, ChannelName)))
		{
			WLog_Print(drdynvc->log, WLOG_ERROR, "dvcman_channel_new failed!");
			*res = CHANNEL_RC_NO_MEMORY;
			goto out;
		}
	}

	if (!HashTable_Insert(dvcman->channelsById, &channel->channel_id, channel))
	{
		WLog_Print(drdynvc->log, WLOG_ERROR, "unable to register channel in our channel list");
		*res = ERROR_INTERNAL_ERROR;
		dvcman_channel_free(channel);
		channel = NULL;
		goto out;
	}

	channel->iface.Write = dvcman_write_channel;
	channel->iface.Close = dvcman_close_channel_iface;
	bAccept = TRUE;

	*res = listener->listener_callback->OnNewChannelConnection(
	    listener->listener_callback, &channel->iface, NULL, &bAccept, &pCallback);

	if (*res != CHANNEL_RC_OK)
	{
		WLog_Print(drdynvc->log, WLOG_ERROR,
		           "OnNewChannelConnection failed with error %" PRIu32 "!", *res);
		*res = ERROR_INTERNAL_ERROR;
		dvcman_channel_unref(channel);
		goto out;
	}

	if (!bAccept)
	{
		WLog_Print(drdynvc->log, WLOG_ERROR, "OnNewChannelConnection returned with bAccept FALSE!");
		*res = ERROR_INTERNAL_ERROR;
		dvcman_channel_unref(channel);
		channel = NULL;
		goto out;
	}

	WLog_Print(drdynvc->log, WLOG_DEBUG, "listener %s created new channel %" PRIu32 "",
	           listener->channel_name, channel->channel_id);
	channel->state = DVC_CHANNEL_RUNNING;
	channel->channel_callback = pCallback;
	channel->pInterface = listener->iface.pInterface;
	context = dvcman->drdynvc->context;

	IFCALLRET(context->OnChannelConnected, *res, context, ChannelName, listener->iface.pInterface);
	if (*res != CHANNEL_RC_OK)
	{
		WLog_Print(drdynvc->log, WLOG_ERROR,
		           "context.OnChannelConnected failed with error %" PRIu32 "", *res);
	}

out:
	HashTable_Unlock(dvcman->listeners);

	return channel;
}
```

Echo 채널을 여는 과정에서 할당 받는 chunk들을 정리하면 다음과 같다.

```python
"""
DVCMAN_CHANNEL (size: 0x80)
0x00 iface.Write       dvcman_write_channel (function)
0x08 iface.Close       dvcman_close_channel_iface (function)
0x10 refCounter
0x14 state
0x18 dvcman            pChannelMgr (global pointer variable)
0x20 pInterface        NULL
0x28 channel_id
0x30 channel_name      "ECHO" (allocated when channel is created)
0x38 channel_callback  callback (GENERIC_CHANNEL_CALLBACK*) (allocated when channel is created)
0x40 dvc_data          NULL 
0x48 dvc_data_length   0x0
0x50 lock              winpr_sem_t (allocated when channel is created)

string (size: 0x20)
0x0 "ECHO"

wKeyValuePair (size: 0x30)
0x00 key 
0x08 value
0x10 next
0x18 markedForRemove

GENERIC_CHANNEL_CALLBACK (size: 0x40)
0x00 iface.OnDataReceived echo_on_data_received
0x08 iface.OnOpen         NULL
0x10 iface.OnClose        echo_on_close
0x18 plugin               listener_callback->plugin (global pointer variable)
0x20 channel_mgr          listener_callback->channel_mgr (global pointer variable)
0x28 channel              &channel->iface (DVCMAN_CHANNEL*) (allocated when channel is created)

union이다
winpr_sem_t (size: 0x30)
0x00 __size
0x00 __align
"""
```

이후 Heap Overflow를 이용한 Vtable Hijacking을 용이하게 하기 위해 0x200개의 ECHO Channel을 열고, 짝수 index의 ECHO Channel만 닫아 heap layout이 다음과 같은 형태를 띄도록 했다.

```python
"""
바이너리에서 heap을 할당하고 해제하는 과정이 매우 많아 
정확하게 이런 모양이 되지는 않는다.

DVCMAN_CHANNEL           (Freed; size: 0x80) 
string                   (Freed; size: 0x20)
wKeyPair								 (Freed; size: 0x30) 
GENERIC_CHANNEL_CALLBACK (Freed; size: 0x40)
winpr_sem_t							 (Freed; size: 0x30) 
DVCMAN_CHANNEL           (Allocated; size: 0x80) 
string                   (Allocated; size: 0x20)
wKeyPair								 (Allocated; size: 0x30) 
GENERIC_CHANNEL_CALLBACK (Allocated; size: 0x40)
winpr_sem_t							 (Allocated; size: 0x30) 
DVCMAN_CHANNEL           (Freed; size: 0x80) 
string                   (Freed; size: 0x20)
wKeyPair								 (Freed; size: 0x30) 
GENERIC_CHANNEL_CALLBACK (Freed; size: 0x40)
winpr_sem_t							 (Freed; size: 0x30) 
DVCMAN_CHANNEL           (Allocated; size: 0x80) 
string                   (Allocated; size: 0x20)
wKeyPair								 (Allocated; size: 0x30) 
GENERIC_CHANNEL_CALLBACK (Allocated; size: 0x40)
winpr_sem_t							 (Allocated; size: 0x30) 

...

DVCMAN_CHANNEL           (Freed; size: 0x80) 
string                   (Freed; size: 0x20)
wKeyPair								 (Freed; size: 0x30) 
GENERIC_CHANNEL_CALLBACK (Freed; size: 0x40)
winpr_sem_t							 (Freed; size: 0x30) 
DVCMAN_CHANNEL           (Allocated; size: 0x80) 
string                   (Allocated; size: 0x20)
wKeyPair								 (Allocated; size: 0x30) 
GENERIC_CHANNEL_CALLBACK (Allocated; size: 0x40)
winpr_sem_t							 (Allocated; size: 0x30) 
"""
```

## Step 3. Overwrite Vtable

이 취약점은 원하는 크기의 chunk를 할당 받아 원하는 크기만큼 원하는 데이터를 쓸 수 있다. Step 2. 에서 만든 heap layout을 이용해 vtable을 hijacking해보자.

Step 2. 에서 높은 확률로 `GENERIC_CHANNEL_CALLBACK (Freed; size: 0x40)` chunk의 바로 앞에 `winpr_sem_t(Allocated; size: 0x30)` 와 `DVCMAN_CHANNEL (Allocated; size: 0x80)` chunk가 있도록 만들었다. 따라서 size가 0x40이 되도록 할당 받고 약간의 overflow를 발생시키면, chunk들을 적게 망치면서 vtable을 hijack할 수 있다.

DEVMAN_CHANNEL 구조체에는 다음과 같은 값이 들어 있었다. 이때 `dvcman_write_channel` 함수를 원하는 주소로 overwrite하고 Echo Channel에 메세지를 보내면 rip를 컨트롤 할 수 있다.

```python
DVCMAN_CHANNEL (size: 0x80)
0x00 iface.Write       dvcman_write_channel (function)
0x08 iface.Close       dvcman_close_channel_iface (function)
0x10 refCounter
0x14 state
0x18 dvcman            pChannelMgr (global pointer variable)
0x20 pInterface        NULL
0x28 channel_id
0x30 channel_name      "ECHO" (allocated when channel is created)
0x38 channel_callback  callback (GENERIC_CHANNEL_CALLBACK*) (allocated when channel is created)
0x40 dvc_data          NULL 
0x48 dvc_data_length   0x0
0x50 lock
```

## Step 4. Pivot & Do ROP

`dvcman_write_channel`의 인자를 살펴보면, 보낸 메세지가 적힌 버퍼의 주소가 rdx에 들어가는 것을 확인할 수 있다.

```c
static UINT dvcman_write_channel(IWTSVirtualChannel* pChannel, 
																ULONG cbSize, const BYTE* pBuffer,
                                 void* pReserved
```

따라서 rdx에 있는 값을 rsp로 옮기면, stack pivoting을 할 수 있다.

Step 1. 에서 library address를 leak 했기 때문에 이런 gadget은 얼마든지 찾아낼 수 있다.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/cec1ad54-477e-4bd4-8219-6ff28cf0771f/Untitled.png)

이때 rdx가 0x10으로 나누어 떨어지지 않아 stack align이 요구되는 `system` 함수 등을 사용하기는 어렵지만, ROP를 수행할 버퍼의 크기가 굉장히 커서 mmap을 이용해 rwx 메모리를 할당하고 shellcode를 쓴 뒤, shellcode로 return하여 RCE를 달성할 수 있었다.





## 실행 환경

### Client

```bash
$ uname -a
Linux u22 5.15.0-48-generic #54-Ubuntu SMP Fri Aug 26 13:26:29 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
$ md5sum /lib/x86_64-linux-gnu/libc.so.6
3d7240354d70ebbd11911187f1acd6e8  /lib/x86_64-linux-gnu/libc.so.6
```

### Server

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2b869786-5f90-4ded-abb3-84988a7f4951/Untitled.png)

## 빌드 방법

```bash
sudo apt-get install -y ninja-build build-essential git-core debhelper cdbs dpkg-dev autotools-dev cmake clang pkg-config xmlto libssl-dev docbook-xsl xsltproc libxkbfile-dev libx11-dev libwayland-dev libxrandr-dev libxi-dev libxrender-dev libxext-dev libxinerama-dev libxfixes-dev libxcursor-dev libxv-dev libxdamage-dev libxtst-dev libcups2-dev libpcsclite-dev libasound2-dev libpulse-dev libjpeg-dev libgsm1-dev libusb-1.0-0-dev libudev-dev libdbus-glib-1-dev uuid-dev libxml2-dev libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libfaad-dev libfaac-dev
sudo apt-get install -y libcunit1-dev libdirectfb-dev xmlto doxygen libxtst-dev
sudo apt-get install -y libavutil-dev libavcodec-dev
git clone <https://github.com/FreeRDP/FreeRDP.git>
cd FreeRDP
git reset --hard a42a765cc3915e5603223d6aee14a1575e611ea8
cmake -G "Eclipse CDT4 - Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug \\
-DCHANNEL_URBDRC=ON -DWITH_FFMPEG=ON -DWITH_CUPS=ON -DWITH_PULSE=ON \\
-DWITH_FAAC=ON -DWITH_FAAD2=ON -DWITH_GSM=ON -DWITH_JPEG=ON \\
-DWITH_MBEDTLS=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \\
-DWITH_SSE2=ON -DCHANNEL_TSMF=ON -DCHANNEL_TSMF_CLIENT=ON \\
-DCHANNEL_RAIL=ON -DCHANNEL_RAIL_CLIENT=ON -B./build .
cmake --build ./build -j 4
sudo cmake --install ./build
```



## 실행 방법

```touch /tmp/poc
xfreerdp /u:<Username> /p:<Password> /v:<Server Address> /parallel:test,/tmp/poc /rfx /gfx /multimedia:decoder:ffmpeg /audio-mode:0 /echo /dynamic-resolution /video
```



