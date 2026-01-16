
// Description: Java 25 JPA Default Factory implementation for ISOCtry.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsec.jpa;

import java.lang.reflect.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;
import io.github.msobkow.v3_1.cfsec.cfsec.*;

/*
 *	CFSecISOCtryFactory JPA implementation for ISOCtry
 */
public class CFSecJpaISOCtryDefaultFactory
    implements ICFSecISOCtryFactory
{
    public CFSecJpaISOCtryDefaultFactory() {
    }

    @Override
    public ICFSecISOCtryHPKey newHPKey() {
        ICFSecISOCtryHPKey hpkey =
            new CFSecJpaISOCtryHPKey();
        return( hpkey );
    }

    @Override
    public ICFSecISOCtryByISOCodeIdxKey newByISOCodeIdxKey() {
	ICFSecISOCtryByISOCodeIdxKey key =
            new CFSecJpaISOCtryByISOCodeIdxKey();
	return( key );
    }

    @Override
    public ICFSecISOCtryByNameIdxKey newByNameIdxKey() {
	ICFSecISOCtryByNameIdxKey key =
            new CFSecJpaISOCtryByNameIdxKey();
	return( key );
    }

    @Override
    public ICFSecISOCtry newRec() {
        ICFSecISOCtry rec =
            new CFSecJpaISOCtry();
        return( rec );
    }

    @Override
    public ICFSecISOCtryH newHRec() {
        ICFSecISOCtryH hrec =
            new CFSecJpaISOCtryH();
        return( hrec );
    }
}
