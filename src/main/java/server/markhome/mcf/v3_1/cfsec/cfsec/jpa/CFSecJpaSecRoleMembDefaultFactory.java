
// Description: Java 25 JPA Default Factory implementation for SecRoleMemb.

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
 *	CFSecSecRoleMembFactory JPA implementation for SecRoleMemb
 */
public class CFSecJpaSecRoleMembDefaultFactory
    implements ICFSecSecRoleMembFactory
{
    public CFSecJpaSecRoleMembDefaultFactory() {
    }

    @Override
    public ICFSecSecRoleMembPKey newPKey() {
        ICFSecSecRoleMembPKey pkey =
            new CFSecJpaSecRoleMembPKey();
        return( pkey );
    }

	public CFSecJpaSecRoleMembPKey ensurePKey(ICFSecSecRoleMembPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecRoleMembPKey) {
			return( (CFSecJpaSecRoleMembPKey)key );
		}
		else {
			CFSecJpaSecRoleMembPKey mapped = new CFSecJpaSecRoleMembPKey();
			mapped.setRequiredContainerRole( key.getRequiredSecRoleId() );
			mapped.setRequiredParentUser( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleMembHPKey newHPKey() {
        ICFSecSecRoleMembHPKey hpkey =
            new CFSecJpaSecRoleMembHPKey();
        return( hpkey );
    }

	public CFSecJpaSecRoleMembHPKey ensureHPKey(ICFSecSecRoleMembHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecRoleMembHPKey) {
			return( (CFSecJpaSecRoleMembHPKey)key );
		}
		else {
			CFSecJpaSecRoleMembHPKey mapped = new CFSecJpaSecRoleMembHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecRoleId( key.getRequiredSecRoleId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleMembByRoleIdxKey newByRoleIdxKey() {
	ICFSecSecRoleMembByRoleIdxKey key =
            new CFSecJpaSecRoleMembByRoleIdxKey();
	return( key );
    }

	public CFSecJpaSecRoleMembByRoleIdxKey ensureByRoleIdxKey(ICFSecSecRoleMembByRoleIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecRoleMembByRoleIdxKey) {
			return( (CFSecJpaSecRoleMembByRoleIdxKey)key );
		}
		else {
			CFSecJpaSecRoleMembByRoleIdxKey mapped = new CFSecJpaSecRoleMembByRoleIdxKey();
			mapped.setRequiredSecRoleId( key.getRequiredSecRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleMembByLoginIdxKey newByLoginIdxKey() {
	ICFSecSecRoleMembByLoginIdxKey key =
            new CFSecJpaSecRoleMembByLoginIdxKey();
	return( key );
    }

	public CFSecJpaSecRoleMembByLoginIdxKey ensureByLoginIdxKey(ICFSecSecRoleMembByLoginIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecRoleMembByLoginIdxKey) {
			return( (CFSecJpaSecRoleMembByLoginIdxKey)key );
		}
		else {
			CFSecJpaSecRoleMembByLoginIdxKey mapped = new CFSecJpaSecRoleMembByLoginIdxKey();
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleMemb newRec() {
        ICFSecSecRoleMemb rec =
            new CFSecJpaSecRoleMemb();
        return( rec );
    }

	public CFSecJpaSecRoleMemb ensureRec(ICFSecSecRoleMemb rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecRoleMemb) {
			return( (CFSecJpaSecRoleMemb)rec );
		}
		else {
			CFSecJpaSecRoleMemb mapped = new CFSecJpaSecRoleMemb();
			mapped.set(rec);
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleMembH newHRec() {
        ICFSecSecRoleMembH hrec =
            new CFSecJpaSecRoleMembH();
        return( hrec );
    }

	public CFSecJpaSecRoleMembH ensureHRec(ICFSecSecRoleMembH hrec) {
		if (hrec == null) {
			return( null );
		}
		else if( hrec instanceof CFSecJpaSecRoleMembH) {
			return( (CFSecJpaSecRoleMembH)hrec );
		}
		else {
			CFSecJpaSecRoleMembH mapped = new CFSecJpaSecRoleMembH();
			mapped.set(hrec);
			return( mapped );
		}
	}
}
