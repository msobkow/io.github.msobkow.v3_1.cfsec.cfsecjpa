
// Description: Java 25 JPA Default Factory implementation for SecSysRole.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.lang.reflect.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/*
 *	CFSecSecSysRoleFactory JPA implementation for SecSysRole
 */
public class CFSecJpaSecSysRoleDefaultFactory
    implements ICFSecSecSysRoleFactory
{
    public CFSecJpaSecSysRoleDefaultFactory() {
    }

    @Override
    public ICFSecSecSysRoleHPKey newHPKey() {
        ICFSecSecSysRoleHPKey hpkey =
            new CFSecJpaSecSysRoleHPKey();
        return( hpkey );
    }

	public CFSecJpaSecSysRoleHPKey ensureHPKey(ICFSecSecSysRoleHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecSysRoleHPKey) {
			return( (CFSecJpaSecSysRoleHPKey)key );
		}
		else {
			CFSecJpaSecSysRoleHPKey mapped = new CFSecJpaSecSysRoleHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecSysRoleId( key.getRequiredSecSysRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleByUNameIdxKey newByUNameIdxKey() {
	ICFSecSecSysRoleByUNameIdxKey key =
            new CFSecJpaSecSysRoleByUNameIdxKey();
	return( key );
    }

	public CFSecJpaSecSysRoleByUNameIdxKey ensureByUNameIdxKey(ICFSecSecSysRoleByUNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysRoleByUNameIdxKey) {
			return( (CFSecJpaSecSysRoleByUNameIdxKey)key );
		}
		else {
			CFSecJpaSecSysRoleByUNameIdxKey mapped = new CFSecJpaSecSysRoleByUNameIdxKey();
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRole newRec() {
        ICFSecSecSysRole rec =
            new CFSecJpaSecSysRole();
        return( rec );
    }

	public CFSecJpaSecSysRole ensureRec(ICFSecSecSysRole rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecSysRole) {
			return( (CFSecJpaSecSysRole)rec );
		}
		else {
			CFSecJpaSecSysRole mapped = new CFSecJpaSecSysRole();
			mapped.set(rec);
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleH newHRec() {
        ICFSecSecSysRoleH hrec =
            new CFSecJpaSecSysRoleH();
        return( hrec );
    }

	public CFSecJpaSecSysRoleH ensureHRec(ICFSecSecSysRoleH hrec) {
		if (hrec == null) {
			return( null );
		}
		else if( hrec instanceof CFSecJpaSecSysRoleH) {
			return( (CFSecJpaSecSysRoleH)hrec );
		}
		else {
			CFSecJpaSecSysRoleH mapped = new CFSecJpaSecSysRoleH();
			mapped.set(hrec);
			return( mapped );
		}
	}
}
