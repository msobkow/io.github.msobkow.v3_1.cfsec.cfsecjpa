
// Description: Java 25 Factory service implementation for SecClusRoleMemb JPA objects

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
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/*
 *	Java 25 Factory service implementation for SecClusRoleMemb JPA objects.
 */
public class CFSecJpaSecClusRoleMembFactoryService
    implements ICFSecSecClusRoleMembFactory
{
    public CFSecJpaSecClusRoleMembFactoryService() { }

    @Override
    public ICFSecSecClusRoleMembPKey newPKey() {
        ICFSecSecClusRoleMembPKey pkey = new CFSecJpaSecClusRoleMembPKey();
        return( pkey );
    }

	public CFSecJpaSecClusRoleMembPKey ensurePKey(ICFSecSecClusRoleMembPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusRoleMembPKey) {
			return( (CFSecJpaSecClusRoleMembPKey)key );
		}
		else {
			CFSecJpaSecClusRoleMembPKey mapped = new CFSecJpaSecClusRoleMembPKey();
			mapped.setRequiredSecClusRoleId( key.getRequiredSecClusRoleId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleMembHPKey newHPKey() {
        ICFSecSecClusRoleMembHPKey hpkey = new CFSecJpaSecClusRoleMembHPKey();
        return( hpkey );
    }

	public CFSecJpaSecClusRoleMembHPKey ensureHPKey(ICFSecSecClusRoleMembHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecClusRoleMembHPKey) {
			return( (CFSecJpaSecClusRoleMembHPKey)key );
		}
		else {
			CFSecJpaSecClusRoleMembHPKey mapped = new CFSecJpaSecClusRoleMembHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecClusRoleId( key.getRequiredSecClusRoleId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleMembByClusRoleIdxKey newByClusRoleIdxKey() {
		ICFSecSecClusRoleMembByClusRoleIdxKey key = new CFSecJpaSecClusRoleMembByClusRoleIdxKey();
	return( key );
    }

	public CFSecJpaSecClusRoleMembByClusRoleIdxKey ensureByClusRoleIdxKey(ICFSecSecClusRoleMembByClusRoleIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusRoleMembByClusRoleIdxKey) {
			return( (CFSecJpaSecClusRoleMembByClusRoleIdxKey)key );
		}
		else {
			CFSecJpaSecClusRoleMembByClusRoleIdxKey mapped = new CFSecJpaSecClusRoleMembByClusRoleIdxKey();
			mapped.setRequiredSecClusRoleId( key.getRequiredSecClusRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleMembByLoginIdxKey newByLoginIdxKey() {
		ICFSecSecClusRoleMembByLoginIdxKey key = new CFSecJpaSecClusRoleMembByLoginIdxKey();
	return( key );
    }

	public CFSecJpaSecClusRoleMembByLoginIdxKey ensureByLoginIdxKey(ICFSecSecClusRoleMembByLoginIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusRoleMembByLoginIdxKey) {
			return( (CFSecJpaSecClusRoleMembByLoginIdxKey)key );
		}
		else {
			CFSecJpaSecClusRoleMembByLoginIdxKey mapped = new CFSecJpaSecClusRoleMembByLoginIdxKey();
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleMemb newRec() {
        ICFSecSecClusRoleMemb rec = new CFSecJpaSecClusRoleMemb();
        return( rec );
    }

	public CFSecJpaSecClusRoleMemb ensureRec(ICFSecSecClusRoleMemb rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecClusRoleMemb) {
			return( (CFSecJpaSecClusRoleMemb)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecClusRoleMemb.CLASS_CODE: {
					CFSecJpaSecClusRoleMemb mapped = new CFSecJpaSecClusRoleMemb();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecClusRoleMemb",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecClusRoleMemb");
			}
		}
	}

    @Override
    public ICFSecSecClusRoleMembH newHRec() {
        ICFSecSecClusRoleMembH hrec = new CFSecJpaSecClusRoleMembH();
        return( hrec );
    }

	public CFSecJpaSecClusRoleMembH ensureHRec(ICFSecSecClusRoleMembH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecClusRoleMembH) {
			return( (CFSecJpaSecClusRoleMembH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecClusRoleMemb.CLASS_CODE: {
					CFSecJpaSecClusRoleMembH mapped = new CFSecJpaSecClusRoleMembH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecClusRoleMemb",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecClusRoleMemb");
			}
		}
	}
}
