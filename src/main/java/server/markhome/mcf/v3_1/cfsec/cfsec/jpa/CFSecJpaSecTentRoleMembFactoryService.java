
// Description: Java 25 Factory service implementation for SecTentRoleMemb JPA objects

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
 *	Java 25 Factory service implementation for SecTentRoleMemb JPA objects.
 */
public class CFSecJpaSecTentRoleMembFactoryService
    implements ICFSecSecTentRoleMembFactory
{
    public CFSecJpaSecTentRoleMembFactoryService() { }

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleMembPKey newPKey() {
        ICFSecSecTentRoleMembPKey pkey = new CFSecJpaSecTentRoleMembPKey();
        return( pkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMembPKey ensurePKey(ICFSecSecTentRoleMembPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentRoleMembPKey) {
			return( (CFSecJpaSecTentRoleMembPKey)key );
		}
		else {
			CFSecJpaSecTentRoleMembPKey mapped = new CFSecJpaSecTentRoleMembPKey();
			mapped.setRequiredSecTentRoleId( key.getRequiredSecTentRoleId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleMembHPKey newHPKey() {
        ICFSecSecTentRoleMembHPKey hpkey = new CFSecJpaSecTentRoleMembHPKey();
        return( hpkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMembHPKey ensureHPKey(ICFSecSecTentRoleMembHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecTentRoleMembHPKey) {
			return( (CFSecJpaSecTentRoleMembHPKey)key );
		}
		else {
			CFSecJpaSecTentRoleMembHPKey mapped = new CFSecJpaSecTentRoleMembHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecTentRoleId( key.getRequiredSecTentRoleId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleMembByTentRoleIdxKey newByTentRoleIdxKey() {
		ICFSecSecTentRoleMembByTentRoleIdxKey key = new CFSecJpaSecTentRoleMembByTentRoleIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMembByTentRoleIdxKey ensureByTentRoleIdxKey(ICFSecSecTentRoleMembByTentRoleIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentRoleMembByTentRoleIdxKey) {
			return( (CFSecJpaSecTentRoleMembByTentRoleIdxKey)key );
		}
		else {
			CFSecJpaSecTentRoleMembByTentRoleIdxKey mapped = new CFSecJpaSecTentRoleMembByTentRoleIdxKey();
			mapped.setRequiredSecTentRoleId( key.getRequiredSecTentRoleId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleMembByUserIdxKey newByUserIdxKey() {
		ICFSecSecTentRoleMembByUserIdxKey key = new CFSecJpaSecTentRoleMembByUserIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMembByUserIdxKey ensureByUserIdxKey(ICFSecSecTentRoleMembByUserIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentRoleMembByUserIdxKey) {
			return( (CFSecJpaSecTentRoleMembByUserIdxKey)key );
		}
		else {
			CFSecJpaSecTentRoleMembByUserIdxKey mapped = new CFSecJpaSecTentRoleMembByUserIdxKey();
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleMemb newRec() {
        ICFSecSecTentRoleMemb rec = new CFSecJpaSecTentRoleMemb();
        return( rec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMemb ensureRec(ICFSecSecTentRoleMemb rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecTentRoleMemb) {
			return( (CFSecJpaSecTentRoleMemb)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecTentRoleMemb.CLASS_CODE: {
					CFSecJpaSecTentRoleMemb mapped = new CFSecJpaSecTentRoleMemb();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecTentRoleMemb",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecTentRoleMemb");
			}
		}
	}

    @Override
    public ICFSecSecTentRoleMembH newHRec() {
        ICFSecSecTentRoleMembH hrec = new CFSecJpaSecTentRoleMembH();
        return( hrec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleMembH ensureHRec(ICFSecSecTentRoleMembH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecTentRoleMembH) {
			return( (CFSecJpaSecTentRoleMembH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecTentRoleMemb.CLASS_CODE: {
					CFSecJpaSecTentRoleMembH mapped = new CFSecJpaSecTentRoleMembH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecTentRoleMemb",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecTentRoleMemb");
			}
		}
	}
}
