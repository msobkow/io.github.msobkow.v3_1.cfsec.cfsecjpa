
// Description: Java 25 Factory service implementation for SecSysRoleEnables JPA objects

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
 *	Java 25 Factory service implementation for SecSysRoleEnables JPA objects.
 */
public class CFSecJpaSecSysRoleEnablesFactoryService
    implements ICFSecSecSysRoleEnablesFactory
{
    public CFSecJpaSecSysRoleEnablesFactoryService() { }

    @Override
    public ICFSecSecSysRoleEnablesPKey newPKey() {
        ICFSecSecSysRoleEnablesPKey pkey = new CFSecJpaSecSysRoleEnablesPKey();
        return( pkey );
    }

	public CFSecJpaSecSysRoleEnablesPKey ensurePKey(ICFSecSecSysRoleEnablesPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysRoleEnablesPKey) {
			return( (CFSecJpaSecSysRoleEnablesPKey)key );
		}
		else {
			CFSecJpaSecSysRoleEnablesPKey mapped = new CFSecJpaSecSysRoleEnablesPKey();
			mapped.setRequiredSecSysRoleId( key.getRequiredSecSysRoleId() );
			mapped.setRequiredEnableName( key.getRequiredEnableName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleEnablesHPKey newHPKey() {
        ICFSecSecSysRoleEnablesHPKey hpkey = new CFSecJpaSecSysRoleEnablesHPKey();
        return( hpkey );
    }

	public CFSecJpaSecSysRoleEnablesHPKey ensureHPKey(ICFSecSecSysRoleEnablesHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecSysRoleEnablesHPKey) {
			return( (CFSecJpaSecSysRoleEnablesHPKey)key );
		}
		else {
			CFSecJpaSecSysRoleEnablesHPKey mapped = new CFSecJpaSecSysRoleEnablesHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecSysRoleId( key.getRequiredSecSysRoleId() );
			mapped.setRequiredEnableName( key.getRequiredEnableName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleEnablesBySysRoleIdxKey newBySysRoleIdxKey() {
		ICFSecSecSysRoleEnablesBySysRoleIdxKey key = new CFSecJpaSecSysRoleEnablesBySysRoleIdxKey();
	return( key );
    }

	public CFSecJpaSecSysRoleEnablesBySysRoleIdxKey ensureBySysRoleIdxKey(ICFSecSecSysRoleEnablesBySysRoleIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysRoleEnablesBySysRoleIdxKey) {
			return( (CFSecJpaSecSysRoleEnablesBySysRoleIdxKey)key );
		}
		else {
			CFSecJpaSecSysRoleEnablesBySysRoleIdxKey mapped = new CFSecJpaSecSysRoleEnablesBySysRoleIdxKey();
			mapped.setRequiredSecSysRoleId( key.getRequiredSecSysRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleEnablesByNameIdxKey newByNameIdxKey() {
		ICFSecSecSysRoleEnablesByNameIdxKey key = new CFSecJpaSecSysRoleEnablesByNameIdxKey();
	return( key );
    }

	public CFSecJpaSecSysRoleEnablesByNameIdxKey ensureByNameIdxKey(ICFSecSecSysRoleEnablesByNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysRoleEnablesByNameIdxKey) {
			return( (CFSecJpaSecSysRoleEnablesByNameIdxKey)key );
		}
		else {
			CFSecJpaSecSysRoleEnablesByNameIdxKey mapped = new CFSecJpaSecSysRoleEnablesByNameIdxKey();
			mapped.setRequiredEnableName( key.getRequiredEnableName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysRoleEnables newRec() {
        ICFSecSecSysRoleEnables rec = new CFSecJpaSecSysRoleEnables();
        return( rec );
    }

	public CFSecJpaSecSysRoleEnables ensureRec(ICFSecSecSysRoleEnables rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecSysRoleEnables) {
			return( (CFSecJpaSecSysRoleEnables)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecSysRoleEnables.CLASS_CODE: {
					CFSecJpaSecSysRoleEnables mapped = new CFSecJpaSecSysRoleEnables();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecSysRoleEnables",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecSysRoleEnables");
			}
		}
	}

    @Override
    public ICFSecSecSysRoleEnablesH newHRec() {
        ICFSecSecSysRoleEnablesH hrec = new CFSecJpaSecSysRoleEnablesH();
        return( hrec );
    }

	public CFSecJpaSecSysRoleEnablesH ensureHRec(ICFSecSecSysRoleEnablesH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecSysRoleEnablesH) {
			return( (CFSecJpaSecSysRoleEnablesH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecSysRoleEnables.CLASS_CODE: {
					CFSecJpaSecSysRoleEnablesH mapped = new CFSecJpaSecSysRoleEnablesH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecSysRoleEnables",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecSysRoleEnables");
			}
		}
	}
}
