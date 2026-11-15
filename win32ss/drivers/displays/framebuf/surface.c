/*
 * ReactOS Generic Framebuffer display driver
 *
 * Copyright (C) 2004 Filip Navara
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "framebuf.h"

/*
 * DrvEnableSurface
 *
 * Set the video mode requested when PDEV was initialized, map the frame
 * buffer and create the screen surface. GDI draws on a copy of the screen
 * in system memory, see shadow.c.
 *
 * Status
 *    @implemented
 */

HSURF APIENTRY
DrvEnableSurface(
   IN DHPDEV dhpdev)
{
   PPDEV ppdev = (PPDEV)dhpdev;
   HSURF hSurface;
   ULONG BitmapType;
   SIZEL ScreenSize;
   VIDEO_MEMORY VideoMemory;
   VIDEO_MEMORY_INFORMATION VideoMemoryInfo;
   ULONG ulTemp;

   /*
    * Set video mode of our adapter.
    */

   if (EngDeviceIoControl(ppdev->hDriver, IOCTL_VIDEO_SET_CURRENT_MODE,
                          &(ppdev->ModeIndex), sizeof(ULONG), NULL, 0,
                          &ulTemp))
   {
      return NULL;
   }

   switch (ppdev->BitsPerPixel)
   {
      case 8:
         BitmapType = BMF_8BPP;
         break;

      case 16:
         BitmapType = BMF_16BPP;
         break;

      case 24:
         BitmapType = BMF_24BPP;
         break;

      case 32:
         BitmapType = BMF_32BPP;
         break;

      default:
         return NULL;
   }

   /*
    * Map the framebuffer into our memory.
    */

   VideoMemory.RequestedVirtualAddress = NULL;
   if (EngDeviceIoControl(ppdev->hDriver, IOCTL_VIDEO_MAP_VIDEO_MEMORY,
                          &VideoMemory, sizeof(VIDEO_MEMORY),
                          &VideoMemoryInfo, sizeof(VIDEO_MEMORY_INFORMATION),
                          &ulTemp))
   {
      return NULL;
   }

   ppdev->ScreenPtr = VideoMemoryInfo.FrameBufferBase;
   ppdev->BytesPerPixel = ppdev->BitsPerPixel / 8;

   if (BitmapType == BMF_8BPP)
   {
      IntSetPalette(dhpdev, ppdev->PaletteEntries, 0, 256);
   }

   ppdev->iDitherFormat = BitmapType;

   ScreenSize.cx = ppdev->ScreenWidth;
   ScreenSize.cy = ppdev->ScreenHeight;

   /*
    * Create the copy of the screen GDI draws on, cleared to black.
    */

   ppdev->hShadow = (HSURF)EngCreateBitmap(ScreenSize, 0, BitmapType,
                                           BMF_TOPDOWN, NULL);
   if (ppdev->hShadow == NULL)
   {
      goto Failure;
   }

   ppdev->psoShadow = EngLockSurface(ppdev->hShadow);
   if (ppdev->psoShadow == NULL)
   {
      goto Failure;
   }

   /*
    * Create the screen surface and associate it with our device.
    */

   hSurface = EngCreateDeviceSurface((DHSURF)ppdev, ScreenSize, BitmapType);
   if (hSurface == NULL)
   {
      goto Failure;
   }

   if (!EngAssociateSurface(hSurface, ppdev->hDevEng,
                            HOOK_BITBLT | HOOK_COPYBITS | HOOK_LINETO |
                            HOOK_ALPHABLEND | HOOK_TRANSPARENTBLT |
                            HOOK_GRADIENTFILL))
   {
      EngDeleteSurface(hSurface);
      goto Failure;
   }

   if (!FbRegisterScreen(ppdev))
   {
      EngDeleteSurface(hSurface);
      goto Failure;
   }

   ppdev->hSurfEng = hSurface;

   /* Start from a black screen, like the shadow */
   ppdev->bScreenEnabled = TRUE;
   FbUpdateWholeScreen(ppdev);

   return hSurface;

Failure:
   if (ppdev->psoShadow != NULL)
   {
      EngUnlockSurface(ppdev->psoShadow);
      ppdev->psoShadow = NULL;
   }

   if (ppdev->hShadow != NULL)
   {
      EngDeleteSurface(ppdev->hShadow);
      ppdev->hShadow = NULL;
   }

   VideoMemory.RequestedVirtualAddress = ppdev->ScreenPtr;
   EngDeviceIoControl(ppdev->hDriver, IOCTL_VIDEO_UNMAP_VIDEO_MEMORY,
                      &VideoMemory, sizeof(VIDEO_MEMORY), NULL, 0, &ulTemp);
   ppdev->ScreenPtr = NULL;

   return NULL;
}

/*
 * DrvDisableSurface
 *
 * Used by GDI to notify a driver that the surface created by DrvEnableSurface
 * for the current device is no longer needed.
 *
 * Status
 *    @implemented
 */

VOID APIENTRY
DrvDisableSurface(
   IN DHPDEV dhpdev)
{
   DWORD ulTemp;
   VIDEO_MEMORY VideoMemory;
   PPDEV ppdev = (PPDEV)dhpdev;

   FbUnregisterScreen(ppdev);
   EngDeleteSurface(ppdev->hSurfEng);
   ppdev->hSurfEng = NULL;
   ppdev->cDirty = 0;

#ifdef EXPERIMENTAL_MOUSE_CURSOR_SUPPORT
   /* Clear all mouse pointer surfaces. */
   DrvSetPointerShape(NULL, NULL, NULL, NULL, 0, 0, 0, 0, NULL, 0);
#endif

   EngUnlockSurface(ppdev->psoShadow);
   ppdev->psoShadow = NULL;
   EngDeleteSurface(ppdev->hShadow);
   ppdev->hShadow = NULL;

   /*
    * Unmap the framebuffer.
    */

   VideoMemory.RequestedVirtualAddress = ((PPDEV)dhpdev)->ScreenPtr;
   EngDeviceIoControl(((PPDEV)dhpdev)->hDriver, IOCTL_VIDEO_UNMAP_VIDEO_MEMORY,
                      &VideoMemory, sizeof(VIDEO_MEMORY), NULL, 0, &ulTemp);
   ppdev->ScreenPtr = NULL;
}

/*
 * DrvAssertMode
 *
 * Sets the mode of the specified physical device to either the mode specified
 * when the PDEV was initialized or to the default mode of the hardware.
 *
 * Status
 *    @implemented
 */

BOOL APIENTRY
DrvAssertMode(
   IN DHPDEV dhpdev,
   IN BOOL bEnable)
{
   PPDEV ppdev = (PPDEV)dhpdev;
   ULONG ulTemp;

   if (bEnable)
   {
      /*
       * Reinitialize the device to a clean state.
       */
      if (EngDeviceIoControl(ppdev->hDriver, IOCTL_VIDEO_SET_CURRENT_MODE,
                             &(ppdev->ModeIndex), sizeof(ULONG), NULL, 0,
                             &ulTemp))
      {
          /* We failed, bail out */
          return FALSE;
      }
      if (ppdev->BitsPerPixel == 8)
      {
	     IntSetPalette(dhpdev, ppdev->PaletteEntries, 0, 256);
      }

      /* The mode set may have cleared the frame buffer, and drawing done
       * while the display was disabled only reached the shadow */
      ppdev->bScreenEnabled = TRUE;
      if (ppdev->psoShadow != NULL)
      {
         FbUpdateWholeScreen(ppdev);
      }

      return TRUE;
   }
   else
   {
      /*
       * Call the miniport driver to reset the device to a known state.
       */
      ppdev->bScreenEnabled = FALSE;
      if (EngDeviceIoControl(ppdev->hDriver, IOCTL_VIDEO_RESET_DEVICE,
                             NULL, 0, NULL, 0, &ulTemp))
      {
         /* The mode is still set */
         ppdev->bScreenEnabled = TRUE;
         return FALSE;
      }

      return TRUE;
   }
}
