
// Description: Java 25 Factory service implementation for SecClusRole JPA objects

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
 *	Java 25 Factory service implementation for SecClusRole JPA objects.
 */
public class CFSecJpaSecClusRoleFactoryService
    implements ICFSecSecClusRoleFactory
{
    public CFSecJpaSecClusRoleFactoryService() { }

    @Override
    public ICFSecSecClusRoleHPKey newHPKey() {
        ICFSecSecClusRoleHPKey hpkey = new CFSecJpaSecClusRoleHPKey();
        return( hpkey );
    }

	public CFSecJpaSecClusRoleHPKey ensureHPKey(ICFSecSecClusRoleHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecClusRoleHPKey) {
			return( (CFSecJpaSecClusRoleHPKey)key );
		}
		else {
			CFSecJpaSecClusRoleHPKey mapped = new CFSecJpaSecClusRoleHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecClusRoleId( key.getRequiredSecClusRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleByClusterIdxKey newByClusterIdxKey() {
		ICFSecSecClusRoleByClusterIdxKey key = new CFSecJpaSecClusRoleByClusterIdxKey();
	return( key );
    }

	public CFSecJpaSecClusRoleByClusterIdxKey ensureByClusterIdxKey(ICFSecSecClusRoleByClusterIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusRoleByClusterIdxKey) {
			return( (CFSecJpaSecClusRoleByClusterIdxKey)key );
		}
		else {
			CFSecJpaSecClusRoleByClusterIdxKey mapped = new CFSecJpaSecClusRoleByClusterIdxKey();
			mapped.setRequiredClusterId( key.getRequiredClusterId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleByNameIdxKey newByNameIdxKey() {
		ICFSecSecClusRoleByNameIdxKey key = new CFSecJpaSecClusRoleByNameIdxKey();
	return( key );
    }

	public CFSecJpaSecClusRoleByNameIdxKey ensureByNameIdxKey(ICFSecSecClusRoleByNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusRoleByNameIdxKey) {
			return( (CFSecJpaSecClusRoleByNameIdxKey)key );
		}
		else {
			CFSecJpaSecClusRoleByNameIdxKey mapped = new CFSecJpaSecClusRoleByNameIdxKey();
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleByUNameIdxKey newByUNameIdxKey() {
		ICFSecSecClusRoleByUNameIdxKey key = new CFSecJpaSecClusRoleByUNameIdxKey();
	return( key );
    }

	public CFSecJpaSecClusRoleByUNameIdxKey ensureByUNameIdxKey(ICFSecSecClusRoleByUNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusRoleByUNameIdxKey) {
			return( (CFSecJpaSecClusRoleByUNameIdxKey)key );
		}
		else {
			CFSecJpaSecClusRoleByUNameIdxKey mapped = new CFSecJpaSecClusRoleByUNameIdxKey();
			mapped.setRequiredClusterId( key.getRequiredClusterId() );
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRole newRec() {
        ICFSecSecClusRole rec = new CFSecJpaSecClusRole();
        return( rec );
    }

	public CFSecJpaSecClusRole ensureRec(ICFSecSecClusRole rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecClusRole) {
			return( (CFSecJpaSecClusRole)rec );
		}
		else {
			CFSecJpaSecClusRole mapped = new CFSecJpaSecClusRole();
			mapped.set(rec);
			return( mapped );
		}
	}

    @Override
    public ICFSecSecClusRoleH newHRec() {
        ICFSecSecClusRoleH hrec = new CFSecJpaSecClusRoleH();
        return( hrec );
    }

	public CFSecJpaSecClusRoleH ensureHRec(ICFSecSecClusRoleH hrec) {
		if (hrec == null) {
			return( null );
		}
		else if( hrec instanceof CFSecJpaSecClusRoleH) {
			return( (CFSecJpaSecClusRoleH)hrec );
		}
		else {
			CFSecJpaSecClusRoleH mapped = new CFSecJpaSecClusRoleH();
			mapped.set(hrec);
			return( mapped );
		}
	}
}
