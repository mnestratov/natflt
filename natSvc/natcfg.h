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

#ifndef _NAT_CONFIG_CLASS_HEADER_
#define _NAT_CONFIG_CLASS_HEADER_


class NATCL_CONFIG
{
public:

    NATCL_CONFIG()
    {
        TCHAR tmpstr[MAX_PATH];
        TCHAR * p;

        if (0 == GetModuleFileName(NULL, tmpstr, MAX_PATH)) {

            memset(s_bin_path, 0, sizeof(s_bin_path));
            memset(s_exe_name, 0, sizeof(s_exe_name));
            return;
        }

        for (p = tmpstr + _tcslen(tmpstr); p > tmpstr; p--)
            if (*p == '\\')
                break;


        if (p == tmpstr) {

            memset(s_bin_path, 0, sizeof(s_bin_path));
            _tcscpy(s_exe_name, tmpstr);
            return;
        }


        *p++ = 0;
        _tcscpy(s_bin_path, tmpstr);
        _tcscpy(s_exe_name, p);

    }

    virtual ~NATCL_CONFIG() {}

    const CHAR * sGetBinPath() const { return s_bin_path; }
    const CHAR * sGetFullName()
    {
        if (strlen(s_bin_path) + strlen(s_exe_name) + 1 < sizeof(s_full_name))
            sprintf(s_full_name, "%s\\%s", s_bin_path, s_exe_name);
        else
            memset(s_full_name, 0, sizeof(s_full_name));

        return s_full_name;
    }

protected:

    TCHAR s_bin_path[MAX_PATH];
    TCHAR s_exe_name[100];

private:

    TCHAR s_full_name[MAX_PATH];

};

extern NATCL_CONFIG nam_cfg;

#endif // _NAT_CONFIG_CLASS_HEADER_

