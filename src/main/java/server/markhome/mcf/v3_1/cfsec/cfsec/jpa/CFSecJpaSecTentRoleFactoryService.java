
// Description: Java 25 Factory service implementation for SecTentRole JPA objects

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
 *	Java 25 Factory service implementation for SecTentRole JPA objects.
 */
public class CFSecJpaSecTentRoleFactoryService
    implements ICFSecSecTentRoleFactory
{
    public CFSecJpaSecTentRoleFactoryService() { }

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleHPKey newHPKey() {
        ICFSecSecTentRoleHPKey hpkey = new CFSecJpaSecTentRoleHPKey();
        return( hpkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleHPKey ensureHPKey(ICFSecSecTentRoleHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecTentRoleHPKey) {
			return( (CFSecJpaSecTentRoleHPKey)key );
		}
		else {
			CFSecJpaSecTentRoleHPKey mapped = new CFSecJpaSecTentRoleHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecTentRoleId( key.getRequiredSecTentRoleId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleByTenantIdxKey newByTenantIdxKey() {
		ICFSecSecTentRoleByTenantIdxKey key = new CFSecJpaSecTentRoleByTenantIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleByTenantIdxKey ensureByTenantIdxKey(ICFSecSecTentRoleByTenantIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentRoleByTenantIdxKey) {
			return( (CFSecJpaSecTentRoleByTenantIdxKey)key );
		}
		else {
			CFSecJpaSecTentRoleByTenantIdxKey mapped = new CFSecJpaSecTentRoleByTenantIdxKey();
			mapped.setRequiredTenantId( key.getRequiredTenantId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleByNameIdxKey newByNameIdxKey() {
		ICFSecSecTentRoleByNameIdxKey key = new CFSecJpaSecTentRoleByNameIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleByNameIdxKey ensureByNameIdxKey(ICFSecSecTentRoleByNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentRoleByNameIdxKey) {
			return( (CFSecJpaSecTentRoleByNameIdxKey)key );
		}
		else {
			CFSecJpaSecTentRoleByNameIdxKey mapped = new CFSecJpaSecTentRoleByNameIdxKey();
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRoleByUNameIdxKey newByUNameIdxKey() {
		ICFSecSecTentRoleByUNameIdxKey key = new CFSecJpaSecTentRoleByUNameIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleByUNameIdxKey ensureByUNameIdxKey(ICFSecSecTentRoleByUNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentRoleByUNameIdxKey) {
			return( (CFSecJpaSecTentRoleByUNameIdxKey)key );
		}
		else {
			CFSecJpaSecTentRoleByUNameIdxKey mapped = new CFSecJpaSecTentRoleByUNameIdxKey();
			mapped.setRequiredTenantId( key.getRequiredTenantId() );
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentRole newRec() {
        ICFSecSecTentRole rec = new CFSecJpaSecTentRole();
        return( rec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole ensureRec(ICFSecSecTentRole rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecTentRole) {
			return( (CFSecJpaSecTentRole)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecTentRole.CLASS_CODE: {
					CFSecJpaSecTentRole mapped = new CFSecJpaSecTentRole();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecTentRole",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecTentRole");
			}
		}
	}

    @Override
    public ICFSecSecTentRoleH newHRec() {
        ICFSecSecTentRoleH hrec = new CFSecJpaSecTentRoleH();
        return( hrec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRoleH ensureHRec(ICFSecSecTentRoleH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecTentRoleH) {
			return( (CFSecJpaSecTentRoleH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecTentRole.CLASS_CODE: {
					CFSecJpaSecTentRoleH mapped = new CFSecJpaSecTentRoleH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecTentRole",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecTentRole");
			}
		}
	}
}
