
// Description: Java 25 Factory service implementation for SecClusGrp JPA objects

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
 *	Java 25 Factory service implementation for SecClusGrp JPA objects.
 */
public class CFSecJpaSecClusGrpFactoryService
    implements ICFSecSecClusGrpFactory
{
    public CFSecJpaSecClusGrpFactoryService() { }

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecClusGrpHPKey newHPKey() {
        ICFSecSecClusGrpHPKey hpkey = new CFSecJpaSecClusGrpHPKey();
        return( hpkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusGrpHPKey ensureHPKey(ICFSecSecClusGrpHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecClusGrpHPKey) {
			return( (CFSecJpaSecClusGrpHPKey)key );
		}
		else {
			CFSecJpaSecClusGrpHPKey mapped = new CFSecJpaSecClusGrpHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecClusGrpId( key.getRequiredSecClusGrpId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecClusGrpByClusterIdxKey newByClusterIdxKey() {
		ICFSecSecClusGrpByClusterIdxKey key = new CFSecJpaSecClusGrpByClusterIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusGrpByClusterIdxKey ensureByClusterIdxKey(ICFSecSecClusGrpByClusterIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusGrpByClusterIdxKey) {
			return( (CFSecJpaSecClusGrpByClusterIdxKey)key );
		}
		else {
			CFSecJpaSecClusGrpByClusterIdxKey mapped = new CFSecJpaSecClusGrpByClusterIdxKey();
			mapped.setRequiredClusterId( key.getRequiredClusterId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecClusGrpByNameIdxKey newByNameIdxKey() {
		ICFSecSecClusGrpByNameIdxKey key = new CFSecJpaSecClusGrpByNameIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusGrpByNameIdxKey ensureByNameIdxKey(ICFSecSecClusGrpByNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusGrpByNameIdxKey) {
			return( (CFSecJpaSecClusGrpByNameIdxKey)key );
		}
		else {
			CFSecJpaSecClusGrpByNameIdxKey mapped = new CFSecJpaSecClusGrpByNameIdxKey();
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecClusGrpByUNameIdxKey newByUNameIdxKey() {
		ICFSecSecClusGrpByUNameIdxKey key = new CFSecJpaSecClusGrpByUNameIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusGrpByUNameIdxKey ensureByUNameIdxKey(ICFSecSecClusGrpByUNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecClusGrpByUNameIdxKey) {
			return( (CFSecJpaSecClusGrpByUNameIdxKey)key );
		}
		else {
			CFSecJpaSecClusGrpByUNameIdxKey mapped = new CFSecJpaSecClusGrpByUNameIdxKey();
			mapped.setRequiredClusterId( key.getRequiredClusterId() );
			mapped.setRequiredName( key.getRequiredName() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecClusGrp newRec() {
        ICFSecSecClusGrp rec = new CFSecJpaSecClusGrp();
        return( rec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusGrp ensureRec(ICFSecSecClusGrp rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecClusGrp) {
			return( (CFSecJpaSecClusGrp)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecClusGrp.CLASS_CODE: {
					CFSecJpaSecClusGrp mapped = new CFSecJpaSecClusGrp();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecClusGrp",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecClusGrp");
			}
		}
	}

    @Override
    public ICFSecSecClusGrpH newHRec() {
        ICFSecSecClusGrpH hrec = new CFSecJpaSecClusGrpH();
        return( hrec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusGrpH ensureHRec(ICFSecSecClusGrpH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecClusGrpH) {
			return( (CFSecJpaSecClusGrpH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecClusGrp.CLASS_CODE: {
					CFSecJpaSecClusGrpH mapped = new CFSecJpaSecClusGrpH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecClusGrp",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecClusGrp");
			}
		}
	}
}
