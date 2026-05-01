
// Description: Java 25 JPA Default Factory implementation for SecRole.

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
 *	CFSecSecRoleFactory JPA implementation for SecRole
 */
public class CFSecJpaSecRoleDefaultFactory
    implements ICFSecSecRoleFactory
{
    public CFSecJpaSecRoleDefaultFactory() {
    }

    @Override
    public ICFSecSecRoleHPKey newHPKey() {
        ICFSecSecRoleHPKey hpkey =
            new CFSecJpaSecRoleHPKey();
        return( hpkey );
    }

	public CFSecJpaSecRoleHPKey ensureHPKey(ICFSecSecRoleHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecRoleHPKey) {
			return( (CFSecJpaSecRoleHPKey)key );
		}
		else {
			CFSecJpaSecRoleHPKey mapped = new CFSecJpaSecRoleHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecRoleId( key.getRequiredSecRoleId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleByUNameIdxKey newByUNameIdxKey() {
	ICFSecSecRoleByUNameIdxKey key =
            new CFSecJpaSecRoleByUNameIdxKey();
	return( key );
    }

	public CFSecJpaSecRoleByUNameIdxKey ensureByUNameIdxKey(ICFSecSecRoleByUNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecRoleByUNameIdxKey) {
			return( (CFSecJpaSecRoleByUNameIdxKey)key );
		}
		else {
			CFSecJpaSecRoleByUNameIdxKey mapped = new CFSecJpaSecRoleByUNameIdxKey();
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRole newRec() {
        ICFSecSecRole rec =
            new CFSecJpaSecRole();
        return( rec );
    }

	public CFSecJpaSecRole ensureRec(ICFSecSecRole rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecRole) {
			return( (CFSecJpaSecRole)rec );
		}
		else {
			CFSecJpaSecRole mapped = new CFSecJpaSecRole();
			mapped.set(rec);
			return( mapped );
		}
	}

    @Override
    public ICFSecSecRoleH newHRec() {
        ICFSecSecRoleH hrec =
            new CFSecJpaSecRoleH();
        return( hrec );
    }

	public CFSecJpaSecRoleH ensureHRec(ICFSecSecRoleH hrec) {
		if (hrec == null) {
			return( null );
		}
		else if( hrec instanceof CFSecJpaSecRoleH) {
			return( (CFSecJpaSecRoleH)hrec );
		}
		else {
			CFSecJpaSecRoleH mapped = new CFSecJpaSecRoleH();
			mapped.set(hrec);
			return( mapped );
		}
	}
}
