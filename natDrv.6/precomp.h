/*
 * Copyright (C) 2015 Maxim Nestratov
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <ndis.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <wwan.h>
#include <ndiswwan.h>

#include "..\natDrvCommon\protos.h"
#include "..\natDrvCommon\natstruct.h"
#include "..\natDrvCommon\pkt.h"
#include "..\natDrvCommon\natdrvio.h"
#include "netgw.h"
