
// Description: Java 25 Factory service implementation for SecSysRoleMemb JPA objects

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/*
 *	Java 25 Factory service implementation for SecSysRoleMemb JPA objects.
 */
public class CFSecJpaSecSysRoleMembFactoryService
    implements ICFSecSecSysRoleMembFactory
{
    public CFSecJpaSecSysRoleMembFactoryService() { }

    @Override
    public ICFSecSecSysRoleMembPKey newPKey() {
        ICFSecSecSysRoleMembPKey pkey = new CFSecJpaSecSysRoleMembPKey();
        return( pkey );
    }

	public CFSecJpaSecSysRoleMembPKey ensurePKey(ICFSecSecSysRoleMembPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysRoleMembPKey) {
			return( (CFSecJpaSecSysRoleMembPKey)key );
		}
		else {
			CFSecJpaSecSysRoleMembPKey mapped = new CFSecJpaSecSysRoleMembPKey();
			mapped.setRequiredSecSysRoleId( key.getRequiredSecSysRoleId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleMembHPKey newHPKey() {
        ICFSecSecSysRoleMembHPKey hpkey = new CFSecJpaSecSysRoleMembHPKey();
        return( hpkey );
    }

	public CFSecJpaSecSysRoleMembHPKey ensureHPKey(ICFSecSecSysRoleMembHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecSysRoleMembHPKey) {
			return( (CFSecJpaSecSysRoleMembHPKey)key );
		}
		else {
			CFSecJpaSecSysRoleMembHPKey mapped = new CFSecJpaSecSysRoleMembHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecSysRoleId( key.getRequiredSecSysRoleId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleMembBySysRoleIdxKey newBySysRoleIdxKey() {
		ICFSecSecSysRoleMembBySysRoleIdxKey key = new CFSecJpaSecSysRoleMembBySysRoleIdxKey();
	return( key );
    }

	public CFSecJpaSecSysRoleMembBySysRoleIdxKey ensureBySysRoleIdxKey(ICFSecSecSysRoleMembBySysRoleIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysRoleMembBySysRoleIdxKey) {
			return( (CFSecJpaSecSysRoleMembBySysRoleIdxKey)key );
		}
		else {
			CFSecJpaSecSysRoleMembBySysRoleIdxKey mapped = new CFSecJpaSecSysRoleMembBySysRoleIdxKey();
			mapped.setRequiredSecSysRoleId( key.getRequiredSecSysRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleMembByLoginIdxKey newByLoginIdxKey() {
		ICFSecSecSysRoleMembByLoginIdxKey key = new CFSecJpaSecSysRoleMembByLoginIdxKey();
	return( key );
    }

	public CFSecJpaSecSysRoleMembByLoginIdxKey ensureByLoginIdxKey(ICFSecSecSysRoleMembByLoginIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysRoleMembByLoginIdxKey) {
			return( (CFSecJpaSecSysRoleMembByLoginIdxKey)key );
		}
		else {
			CFSecJpaSecSysRoleMembByLoginIdxKey mapped = new CFSecJpaSecSysRoleMembByLoginIdxKey();
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleMemb newRec() {
        ICFSecSecSysRoleMemb rec = new CFSecJpaSecSysRoleMemb();
        return( rec );
    }

	public CFSecJpaSecSysRoleMemb ensureRec(ICFSecSecSysRoleMemb rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecSysRoleMemb) {
			return( (CFSecJpaSecSysRoleMemb)rec );
		}
		else {
			CFSecJpaSecSysRoleMemb mapped = new CFSecJpaSecSysRoleMemb();
			mapped.set(rec);
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleMembH newHRec() {
        ICFSecSecSysRoleMembH hrec = new CFSecJpaSecSysRoleMembH();
        return( hrec );
    }

	public CFSecJpaSecSysRoleMembH ensureHRec(ICFSecSecSysRoleMembH hrec) {
		if (hrec == null) {
			return( null );
		}
		else if( hrec instanceof CFSecJpaSecSysRoleMembH) {
			return( (CFSecJpaSecSysRoleMembH)hrec );
		}
		else {
			CFSecJpaSecSysRoleMembH mapped = new CFSecJpaSecSysRoleMembH();
			mapped.set(hrec);
			return( mapped );
		}
	}
}
