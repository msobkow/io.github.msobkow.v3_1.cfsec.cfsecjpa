
// Description: Java 25 Factory service implementation for SecTentGrp JPA objects

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
 *	Java 25 Factory service implementation for SecTentGrp JPA objects.
 */
public class CFSecJpaSecTentGrpFactoryService
    implements ICFSecSecTentGrpFactory
{
    public CFSecJpaSecTentGrpFactoryService() { }

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentGrpHPKey newHPKey() {
        ICFSecSecTentGrpHPKey hpkey = new CFSecJpaSecTentGrpHPKey();
        return( hpkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentGrpHPKey ensureHPKey(ICFSecSecTentGrpHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecTentGrpHPKey) {
			return( (CFSecJpaSecTentGrpHPKey)key );
		}
		else {
			CFSecJpaSecTentGrpHPKey mapped = new CFSecJpaSecTentGrpHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecTentGrpId( key.getRequiredSecTentGrpId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentGrpByTenantIdxKey newByTenantIdxKey() {
		ICFSecSecTentGrpByTenantIdxKey key = new CFSecJpaSecTentGrpByTenantIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentGrpByTenantIdxKey ensureByTenantIdxKey(ICFSecSecTentGrpByTenantIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentGrpByTenantIdxKey) {
			return( (CFSecJpaSecTentGrpByTenantIdxKey)key );
		}
		else {
			CFSecJpaSecTentGrpByTenantIdxKey mapped = new CFSecJpaSecTentGrpByTenantIdxKey();
			mapped.setRequiredTenantId( key.getRequiredTenantId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentGrpByNameIdxKey newByNameIdxKey() {
		ICFSecSecTentGrpByNameIdxKey key = new CFSecJpaSecTentGrpByNameIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentGrpByNameIdxKey ensureByNameIdxKey(ICFSecSecTentGrpByNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentGrpByNameIdxKey) {
			return( (CFSecJpaSecTentGrpByNameIdxKey)key );
		}
		else {
			CFSecJpaSecTentGrpByNameIdxKey mapped = new CFSecJpaSecTentGrpByNameIdxKey();
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentGrpByUNameIdxKey newByUNameIdxKey() {
		ICFSecSecTentGrpByUNameIdxKey key = new CFSecJpaSecTentGrpByUNameIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentGrpByUNameIdxKey ensureByUNameIdxKey(ICFSecSecTentGrpByUNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecTentGrpByUNameIdxKey) {
			return( (CFSecJpaSecTentGrpByUNameIdxKey)key );
		}
		else {
			CFSecJpaSecTentGrpByUNameIdxKey mapped = new CFSecJpaSecTentGrpByUNameIdxKey();
			mapped.setRequiredTenantId( key.getRequiredTenantId() );
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecTentGrp newRec() {
        ICFSecSecTentGrp rec = new CFSecJpaSecTentGrp();
        return( rec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentGrp ensureRec(ICFSecSecTentGrp rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecTentGrp) {
			return( (CFSecJpaSecTentGrp)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecTentGrp.CLASS_CODE: {
					CFSecJpaSecTentGrp mapped = new CFSecJpaSecTentGrp();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecTentGrp",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecTentGrp");
			}
		}
	}

    @Override
    public ICFSecSecTentGrpH newHRec() {
        ICFSecSecTentGrpH hrec = new CFSecJpaSecTentGrpH();
        return( hrec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentGrpH ensureHRec(ICFSecSecTentGrpH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecTentGrpH) {
			return( (CFSecJpaSecTentGrpH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecTentGrp.CLASS_CODE: {
					CFSecJpaSecTentGrpH mapped = new CFSecJpaSecTentGrpH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecTentGrp",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecTentGrp");
			}
		}
	}
}
