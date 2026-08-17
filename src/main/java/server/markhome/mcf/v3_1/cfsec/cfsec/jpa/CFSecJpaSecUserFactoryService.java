
// Description: Java 25 Factory service implementation for SecUser JPA objects

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
 *	Java 25 Factory service implementation for SecUser JPA objects.
 */
public class CFSecJpaSecUserFactoryService
    implements ICFSecSecUserFactory
{
    public CFSecJpaSecUserFactoryService() { }

    @Override
    public ICFSecSecUserHPKey newHPKey() {
        ICFSecSecUserHPKey hpkey = new CFSecJpaSecUserHPKey();
        return( hpkey );
    }

	public CFSecJpaSecUserHPKey ensureHPKey(ICFSecSecUserHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecUserHPKey) {
			return( (CFSecJpaSecUserHPKey)key );
		}
		else {
			CFSecJpaSecUserHPKey mapped = new CFSecJpaSecUserHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecUserId( key.getRequiredSecUserId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecUserByULoginIdxKey newByULoginIdxKey() {
		ICFSecSecUserByULoginIdxKey key = new CFSecJpaSecUserByULoginIdxKey();
	return( key );
    }

	public CFSecJpaSecUserByULoginIdxKey ensureByULoginIdxKey(ICFSecSecUserByULoginIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecUserByULoginIdxKey) {
			return( (CFSecJpaSecUserByULoginIdxKey)key );
		}
		else {
			CFSecJpaSecUserByULoginIdxKey mapped = new CFSecJpaSecUserByULoginIdxKey();
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecUserByEMAddrIdxKey newByEMAddrIdxKey() {
		ICFSecSecUserByEMAddrIdxKey key = new CFSecJpaSecUserByEMAddrIdxKey();
	return( key );
    }

	public CFSecJpaSecUserByEMAddrIdxKey ensureByEMAddrIdxKey(ICFSecSecUserByEMAddrIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecUserByEMAddrIdxKey) {
			return( (CFSecJpaSecUserByEMAddrIdxKey)key );
		}
		else {
			CFSecJpaSecUserByEMAddrIdxKey mapped = new CFSecJpaSecUserByEMAddrIdxKey();
			mapped.setRequiredEMailAddress( key.getRequiredEMailAddress() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecUser newRec() {
        ICFSecSecUser rec = new CFSecJpaSecUser();
        return( rec );
    }

	public CFSecJpaSecUser ensureRec(ICFSecSecUser rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecUser) {
			return( (CFSecJpaSecUser)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecUser.CLASS_CODE: {
					CFSecJpaSecUser mapped = new CFSecJpaSecUser();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecUser",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecUser");
			}
		}
	}

    @Override
    public ICFSecSecUserH newHRec() {
        ICFSecSecUserH hrec = new CFSecJpaSecUserH();
        return( hrec );
    }

	public CFSecJpaSecUserH ensureHRec(ICFSecSecUserH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecUserH) {
			return( (CFSecJpaSecUserH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecUser.CLASS_CODE: {
					CFSecJpaSecUserH mapped = new CFSecJpaSecUserH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecUser",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecUser");
			}
		}
	}
}
