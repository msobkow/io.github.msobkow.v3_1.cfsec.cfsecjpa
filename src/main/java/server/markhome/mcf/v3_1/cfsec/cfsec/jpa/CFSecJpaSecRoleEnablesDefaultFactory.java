
// Description: Java 25 JPA Default Factory implementation for SecRoleEnables.

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
 *	CFSecSecRoleEnablesFactory JPA implementation for SecRoleEnables
 */
public class CFSecJpaSecRoleEnablesDefaultFactory
    implements ICFSecSecRoleEnablesFactory
{
    public CFSecJpaSecRoleEnablesDefaultFactory() {
    }

    @Override
    public ICFSecSecRoleEnablesPKey newPKey() {
        ICFSecSecRoleEnablesPKey pkey =
            new CFSecJpaSecRoleEnablesPKey();
        return( pkey );
    }

	public CFSecJpaSecRoleEnablesPKey ensurePKey(ICFSecSecRoleEnablesPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecRoleEnablesPKey) {
			return( (CFSecJpaSecRoleEnablesPKey)key );
		}
		else {
			CFSecJpaSecRoleEnablesPKey mapped = new CFSecJpaSecRoleEnablesPKey();
			mapped.setRequiredContainerRole( key.getRequiredSecRoleId() );
			mapped.setRequiredParentEnableGroup( key.getRequiredEnableName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleEnablesHPKey newHPKey() {
        ICFSecSecRoleEnablesHPKey hpkey =
            new CFSecJpaSecRoleEnablesHPKey();
        return( hpkey );
    }

	public CFSecJpaSecRoleEnablesHPKey ensureHPKey(ICFSecSecRoleEnablesHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecRoleEnablesHPKey) {
			return( (CFSecJpaSecRoleEnablesHPKey)key );
		}
		else {
			CFSecJpaSecRoleEnablesHPKey mapped = new CFSecJpaSecRoleEnablesHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecRoleId( key.getRequiredSecRoleId() );
			mapped.setRequiredEnableName( key.getRequiredEnableName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleEnablesByRoleIdxKey newByRoleIdxKey() {
	ICFSecSecRoleEnablesByRoleIdxKey key =
            new CFSecJpaSecRoleEnablesByRoleIdxKey();
	return( key );
    }

	public CFSecJpaSecRoleEnablesByRoleIdxKey ensureByRoleIdxKey(ICFSecSecRoleEnablesByRoleIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecRoleEnablesByRoleIdxKey) {
			return( (CFSecJpaSecRoleEnablesByRoleIdxKey)key );
		}
		else {
			CFSecJpaSecRoleEnablesByRoleIdxKey mapped = new CFSecJpaSecRoleEnablesByRoleIdxKey();
			mapped.setRequiredSecRoleId( key.getRequiredSecRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleEnablesByNameIdxKey newByNameIdxKey() {
	ICFSecSecRoleEnablesByNameIdxKey key =
            new CFSecJpaSecRoleEnablesByNameIdxKey();
	return( key );
    }

	public CFSecJpaSecRoleEnablesByNameIdxKey ensureByNameIdxKey(ICFSecSecRoleEnablesByNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecRoleEnablesByNameIdxKey) {
			return( (CFSecJpaSecRoleEnablesByNameIdxKey)key );
		}
		else {
			CFSecJpaSecRoleEnablesByNameIdxKey mapped = new CFSecJpaSecRoleEnablesByNameIdxKey();
			mapped.setRequiredEnableName( key.getRequiredEnableName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleEnables newRec() {
        ICFSecSecRoleEnables rec =
            new CFSecJpaSecRoleEnables();
        return( rec );
    }

	public CFSecJpaSecRoleEnables ensureRec(ICFSecSecRoleEnables rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecRoleEnables) {
			return( (CFSecJpaSecRoleEnables)rec );
		}
		else {
			CFSecJpaSecRoleEnables mapped = new CFSecJpaSecRoleEnables();
			mapped.set(rec);
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleEnablesH newHRec() {
        ICFSecSecRoleEnablesH hrec =
            new CFSecJpaSecRoleEnablesH();
        return( hrec );
    }

	public CFSecJpaSecRoleEnablesH ensureHRec(ICFSecSecRoleEnablesH hrec) {
		if (hrec == null) {
			return( null );
		}
		else if( hrec instanceof CFSecJpaSecRoleEnablesH) {
			return( (CFSecJpaSecRoleEnablesH)hrec );
		}
		else {
			CFSecJpaSecRoleEnablesH mapped = new CFSecJpaSecRoleEnablesH();
			mapped.set(hrec);
			return( mapped );
		}
	}
}
